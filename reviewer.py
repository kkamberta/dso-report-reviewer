#!/usr/bin/env python3
# DSO Report Reviewer — automates security findings triage using Claude LLM.
# Fills: Asset Importance, Compensation Control, Residual Severity in the XLSX.
#
# Requires: ANTHROPIC_API_KEY environment variable
#
# Usage:
#   python reviewer.py --input Summary-Report_BuildNumberXXXXX.xlsx --config priority.yaml
#   python reviewer.py --input report.xlsx --config priority.yaml --project ap2065

import argparse
import json
import logging
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import anthropic
import openpyxl
import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
log = logging.getLogger(__name__)

CHUNK_SIZE = int(os.getenv("REVIEWER_CHUNK_SIZE", "50"))

# ponytail: simple mutable counter — thread-safe for += on CPython GIL, good enough here
_token_usage = {"input": 0, "output": 0, "calls": 0}
MODEL = os.getenv("REVIEWER_MODEL", "claude-sonnet-4-6")
MAX_RETRIES = int(os.getenv("REVIEWER_MAX_RETRIES", "1"))
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

# Sheet name → primary identifier column (used for project code extraction in container sheets)
SHEET_ID_COL = {
    "Blackduck": "Archive Context and Path",
    "Coverity": "Path Source",
    "CheckpointCve": "ImageName",
    "CheckpointSecret": "id",
    "CheckpointThreat": "name",
}

# Fields sent to Claude per sheet — strips verbose Description columns to keep prompt size manageable
TRIAGE_FIELDS = {
    "Blackduck": [
        "row_id", "Libraries", "Version", "CVE Name", "CVSS Score",
        "Exploit available", "Match type", "Short Term Recommended",
        "Severity", "Asset Importance",
    ],
    "Coverity": [
        "row_id", "Issue Name", "Path Source", "Classification",
        "Issue Kind", "OWASP Top10 category", "Remediation",
        "Severity", "Asset Importance",
    ],
    "CheckpointCve": [
        "row_id", "ImageName", "name", "type", "baseScore",
        "PackageName", "PackageVersion", "remediation",
        "Is OS Package", "severity", "Asset Importance",
    ],
    "CheckpointSecret": [
        "row_id", "name", "description", "type",
        "secretFilePath", "remediation", "severity", "Asset Importance",
    ],
    "CheckpointThreat": [
        "row_id", "threatType", "threatClassification",
        "description", "remediation", "FilePath", "severity", "Asset Importance",
    ],
}

# ── System prompts (stable per sheet type → cached by Claude) ─────────────────

_RESPONSE_FORMAT = """
## Response format

Return ONLY a valid JSON array — no markdown fences, no commentary, no preamble. Raw JSON only.
One object per finding, in this exact schema:

[
  {
    "row_id": <integer — echo back unchanged>,
    "compensation_control": "<1-2 sentences: specific mitigation or accepted-risk rationale>",
    "residual_severity": "<Critical|High|Medium|Low|Info>"
  }
]

## Severity definitions

- Critical: Immediate exploitation possible, high business impact, no mitigating factors present.
- High: Exploitable with moderate difficulty or significant business impact.
- Medium: Limited exploitability or limited impact; compensating controls reduce risk materially.
- Low: Theoretical risk, difficult to exploit, or compensating controls largely neutralise the threat.
- Info: False positive confirmed, test/dev-only asset, or risk fully accepted with documented rationale.

## Compensation control writing rules

1. If a fix version exists: "Upgrade <component> to <version> to remediate <issue>."
2. If remediation says patch or upgrade to a fixed version, include one executable technical command in the same sentence when the package ecosystem is clear, for example `mvn versions:use-dep-version ...`, `npm install <package>@<version>`, `python -m pip install --upgrade '<package>==<version>'`, `apk upgrade --no-cache <package>`, or `dnf update -y <package>`.
3. If the exact package manager is not clear, state the exact dependency/version and say to update the lock file through the project's native package manager; do not invent a repository, image tag, or endpoint.
4. If risk is accepted: "Accepted: <brief rationale>. Schedule review when fix is available."
5. If compensated by a control: "Compensated by <WAF rule / network policy / rotation>. Residual risk reduced to <severity>."
6. If false positive: "False positive: <brief reason e.g. test code, framework asset, unused package>."
7. Always be specific. Never write generic phrases like 'apply security patches' or 'follow best practices'.
"""


def _blackduck_prompt() -> str:
    return """You are a senior application security engineer specialising in Software Composition Analysis (SCA).
You are triaging Blackduck scan findings — known vulnerabilities in open-source libraries used by the application.

## Domain knowledge

### CVSS score thresholds
- 9.0–10.0: Network-reachable, zero authentication, full impact. Treat as Critical. Do not downgrade unless the vulnerable
  code path is demonstrably unreachable in the deployed application.
- 7.0–8.9: High exploitability. Upgrade is required. Accepted risk is permissible only for low-priority assets when
  no fix exists and the deployment environment has compensating network controls.
- 4.0–6.9: Limited scope or requires authentication. A compensating control (WAF rule, network segmentation,
  authentication enforcement) can reduce to Medium or Low.
- 0.1–3.9: Theoretical risk. Document and accept unless the library is directly exposed to user input.

### Exploit availability
- Exploit available = True: Public exploits exist. Real-world attack probability is high. Do not downgrade
  Critical or High findings based on CVSS alone — treat as actively exploitable.
- Exploit available = False: Can downgrade by one severity level for non-critical assets when no fix exists,
  but only if the library is not directly internet-exposed.

### Dependency type
- Direct Dependency: Developer explicitly imported this library. Upgrade via package manager is straightforward.
  compensation_control must recommend upgrading to the version in "Short Term Recommended".
- Transitive Dependency: Pulled in by another library. Upgrading the parent dependency or forcing a version
  override may be required. Note this complexity in compensation_control.

### Fix availability
- If Short Term Recommended contains a version string: always include "Upgrade <library> to <version>" in
  compensation_control.
- If no fix version is available: accept with rationale and request developer to monitor for upstream patch.
  Suggest alternative library if the current one is unmaintained.

### Archive Context and Path analysis
- Paths containing "/test/", "/-test/", "test scope" in Maven/Gradle context: test-only dependency.
  Downgrade by one level — test dependencies are not deployed to production.
- Build tool dependencies (e.g., jest, webpack, babel in devDependencies): not present at runtime.
  Downgrade to Low or Info.
- Paths pointing to archived or vendor directories not deployed at runtime: note as non-production asset.

### Asset importance influence
- High: Maintain or escalate severity. No accepted-risk downgrades for Critical/High findings.
  Compensating controls must be specific and include a remediation timeline.
- Low: Accepted risk permissible for Medium and Low findings without public exploits.
  Document the acceptance rationale clearly.

""" + _RESPONSE_FORMAT


def _coverity_prompt() -> str:
    return """You are a senior application security engineer specialising in Static Application Security Testing (SAST).
You are triaging Coverity findings — code-level security defects identified through static analysis.

## Domain knowledge

### Classification field interpretation
- Unclassified: The finding has not been reviewed by a developer. Apply normal triage. Many Coverity findings
  in this state are valid but unconfirmed. Do not discount unless there is clear evidence of a false positive.
- Intentional: Developer marked this as intended behavior. Downgrade to Info unless the intent contradicts
  a security policy (e.g., intentional use of MD5 for password hashing).
- Bug: Confirmed defect. Maintain or escalate severity based on OWASP category and exploitability.
- Pending: Under developer review. Keep original severity until classification is confirmed.

### Issue Kind
- Security: Directly exploitable vulnerability class. Maintain or escalate severity.
- Quality: Code quality issue with security implications (e.g., null dereference leading to DoS).
  Can downgrade one level below original severity.

### OWASP Top 10 mapping
- A1 Broken Access Control: High or Critical if access control logic is bypassed. High risk category.
- A2 Cryptographic Failures: High if production credentials or PII are exposed. Medium for weak hashing
  of non-sensitive data.
- A3 Injection (SQL, command, LDAP, XSS): High or Critical. Maintain severity — injection findings
  in unclassified state are often valid.
- A4 Insecure Design: Context-dependent. High if authentication or authorisation flow is flawed.
- A5 Security Misconfiguration: Medium by default. High if the misconfiguration directly exposes
  production data or admin functionality.
- A6 Vulnerable Components: Already covered by SCA. If Coverity flags this independently, correlate
  with Blackduck findings before setting residual severity.
- A7 Identification and Authentication Failures: High for authentication code paths. Medium for
  internal service-to-service APIs.
- A8 Software and Data Integrity Failures: Medium. Compensate with code signing or integrity checks.
- A9 Security Logging and Monitoring: Low or Medium. Note the logging gap in compensation_control.
- A10 SSRF: High if user-controlled URLs can reach internal services. Medium otherwise.

### Path Source analysis
- Test files ("/test/", "/spec/", "/__tests__/", ".test.js", "Test.java"): Significant false positive
  risk. Downgrade to Info if the finding is exclusively in test code.
- Vendor or third-party directories ("/vendor/", "/node_modules/", "/third-party/"): Finding is in
  dependency code the team does not control. Downgrade by one level and note in compensation_control
  that fixing requires upgrading the dependency.
- Configuration files (application.yml, .properties) with hard-coded credentials: High or Critical
  regardless of path. These are real secrets that must be removed and rotated.

### Remediation field
- Contains "ID : <number> on index.html": This is a Coverity-generated guidance reference.
  Include "Follow Coverity remediation guidance ID <number>" in compensation_control.

### Asset importance influence
- High: Strict triage. Unclassified injection and broken access control findings default to High.
  No downgrading based solely on path heuristics without developer confirmation.
- Low: Unclassified findings in vendor/third-party paths may be downgraded one level.
  Document the heuristic used for the downgrade.

""" + _RESPONSE_FORMAT


def _checkpoint_cve_prompt() -> str:
    return """You are a senior application security engineer specialising in container image security.
You are triaging CheckPoint CloudGuard CVE findings — vulnerabilities in packages installed inside
Docker/OCI container images deployed to production or staging environments.

## Domain knowledge

### CVSS base score (baseScore field)
- 9.0–10.0: Network-reachable, no authentication required, full system impact. Treat as Critical.
  Base image rebuild or immediate patching is required.
- 7.0–8.9: High exploitability. Upgrade required within the current sprint.
- 4.0–6.9: Requires specific conditions or limited impact. Compensating controls may reduce to Low.
- 0.1–3.9: Theoretical risk. Accept with documentation unless the package is directly user-facing.
- "No CVSS Score" or null: Newly published CVE without official scoring. Treat as Medium pending
  the official score. Note this ambiguity in compensation_control.

### OS Package vs Application Package
- Is OS Package = True: The vulnerability is in the base OS layer (e.g., OpenSSL, glibc, bash, curl).
  Fixing requires rebuilding the container with an updated base image. compensation_control must
  recommend "Rebuild container using an updated base image that includes <package> >= <version>."
- Is OS Package = False: The vulnerability is in an application-level package (e.g., a Java JAR,
  Node.js module, or Python wheel). Fixing may be possible via application dependency upgrade
  without rebuilding the base image.

### Remediation field
- If the remediation field specifies an upgrade version (e.g., "Upgrade to 3.3.6-r0"): use this
  as the primary content of compensation_control.
- If remediation is null or generic: recommend "Rebuild container with a base image that patches
  <package>. Monitor vendor advisory for a fix."

### Container exposure context
- Internet-facing containers: API services, web frontends, ingress proxies — identified by image
  names containing patterns like "-api", "-fe", "-web", "-gateway", "nginx", "haproxy".
  Maintain or escalate severity. These containers are reachable from the public internet.
- Internal services, batch jobs, init containers: Less directly reachable. Can downgrade Medium
  and Low CVEs by one level when no exploit is known.

### Common patterns
- CVEs in packages installed but unused at runtime (e.g., build tools left in production images):
  Note the unused package status. Recommend removing the package from the production image.
  Downgrade by one level.
- Multiple CVEs fixed by a single package upgrade: group them in the compensation_control.
  Example: "Upgrade libcrypto3 to 3.3.6-r0 (fixes CVE-2025-15467 Critical, CVE-2025-9230 High, +11 more)."

### Asset importance influence
- High: No downgrading of Critical CVEs. High CVEs require an upgrade plan in compensation_control.
- Low: Medium CVEs in OS packages with no known exploits may be accepted if base image rebuild
  has significant operational cost. Document clearly.

""" + _RESPONSE_FORMAT


def _checkpoint_secret_prompt() -> str:
    return """You are a senior application security engineer specialising in secrets detection in container images.
You are triaging CheckPoint CloudGuard secrets findings — hardcoded credentials, API keys, private keys,
or sensitive strings detected inside deployed container image filesystems.

## Domain knowledge

### Secret type severity mapping
- private_key / certificate private key: Always Critical. A private key embedded in a container image
  can be extracted by anyone who can pull the image. Immediate revocation of the key and removal
  from source code is required.
- API keys, access tokens, bearer tokens, passwords: High. Must be rotated immediately and
  replaced with runtime injection via a secrets manager.
- "Possible hardcoded secret" (generic detection): Medium. Requires investigation — may be a
  placeholder value, an example in documentation, or a real credential. The compensation_control
  must request developer investigation.
- Connection strings containing credentials: High for production databases. Medium for
  development/staging environments.
- Certificate files (.crt, .pem without private key): Low or Info — public certificates are
  intentionally distributed. Distinguish from .key files which contain private material.

### File path sensitivity analysis
- Production configuration (application.yml, application.properties, *.prod.*, *.production.*):
  High or Critical — these are live credentials deployed to production.
- Development/staging configuration (application-dev.yml, application-sit.yml, *-test.*, *-staging.*):
  Medium — lower immediate risk but poor security practice that must be remediated.
- Test fixtures, example files, documentation ("example", "sample", "demo", "README"):
  Low or Info — likely intentional placeholders. Note the suspicion but downgrade.
- Framework-bundled files (e.g., PHPExcel libraries, tcpdf, DOMPDF assets, third-party PDFs):
  Info — these are framework assets shipped with the library, not application secrets.
  Mark as false positive with rationale.
- Files inside BOOT-INF/classes (Spring Boot fat JARs): These are application config files
  bundled into the JAR at build time. Treat the same as the config file type — dev/sit = Medium,
  prod = High.

### Compensation control for secrets
- For confirmed secrets: "Remove secret from <file path>, rotate the credential immediately,
  and inject at runtime using a secrets manager (Vault, AWS SSM, Azure Key Vault, Kubernetes Secret)."
- For false positives (framework assets): "False positive: this is a <framework> library asset,
  not an application secret."
- For 'possible' secrets requiring investigation: "Investigate <file path> line <lines> to confirm
  whether this is a real credential. If confirmed, rotate and remove from codebase."

### Asset importance influence
- High: No acceptance of secret findings. All secrets are Critical or High. Framework false positives
  are still Info — do not escalate those.
- Low: Medium findings in non-production config files may be accepted with a rotation schedule,
  but must still be remediated in the next sprint.

""" + _RESPONSE_FORMAT


def _checkpoint_threat_prompt() -> str:
    return """You are a senior application security engineer specialising in malware and threat detection in container images.
You are triaging CheckPoint CloudGuard threat findings — potential malware signatures, malicious URLs,
or threat indicators detected inside deployed container image filesystems.

## Domain knowledge

### Threat type severity mapping
- Malware (confirmed signature match): Critical. The container image is potentially compromised.
  Do not deploy. Rebuild from a verified base image and investigate the supply chain.
- Trojan / Backdoor: Critical. Indicates supply chain compromise. Treat as a security incident.
- Infecting URL (known malicious domain or C2 server in source code): High. The code references
  a malicious endpoint. Immediate investigation required — assess whether the URL is called at runtime.
- Adware: Medium. Indicates supply chain issue. Investigate and remove.
- Suspicious script (heuristic match, not confirmed): Medium. Requires manual review to confirm.
  Mark as false positive only after developer investigation confirms the code is benign.

### Payload and URL analysis
- Known CDN domains (cdnjs.cloudflare.com, cdn.jsdelivr.net, unpkg.com, cdn.bootcdn.net):
  Almost always legitimate CDN references for frontend libraries. Mark as false positive if the
  domain is a known reputable CDN. Note: verify the specific URL has not been hijacked.
- File-sharing / cloud storage URLs in source code (dl.dropboxusercontent.com, drive.google.com,
  Pastebin, GitHub Gist raw URLs): Suspicious — potential data exfiltration vector or
  payload dropper. High severity. Investigate the URL content.
- The specific URL at issue is in the 'payload' field. Assess its reputation.

### File path context
- FilePath in commented-out code or documentation: Lower risk — not called at runtime.
  Downgrade by one level but still require removal.
- FilePath in active JavaScript, Python, or shell scripts: Higher risk — may be called at runtime.
  Maintain severity.
- Third-party library paths (e.g., Chart.js, jQuery plugins, CKEditor): The threat is inside a
  dependency, not application code. Note this in compensation_control — upgrading or replacing
  the library is the fix.

### Compensation control for threat findings
- For confirmed malicious findings: "Remove container image from registry immediately. Rebuild from
  a verified base image. Investigate supply chain for compromise. File a security incident report."
- For suspicious CDN URLs: "Verify domain reputation of <domain>. If confirmed as a legitimate CDN,
  mark as false positive. If domain is compromised, remove and replace the library."
- For Infecting URL in third-party library: "Upgrade <library name> to a version that does not
  contain the malicious reference. Verify the updated version is clean."

### Asset importance influence
- High: Malware and backdoor findings are always Critical regardless of asset importance.
  Infecting URL findings remain High. No downgrading of confirmed threat indicators.
- Low: Suspicious script heuristic matches may be downgraded to Low pending developer investigation.

""" + _RESPONSE_FORMAT


_SYSTEM_PROMPTS = {
    "Blackduck": _blackduck_prompt(),
    "Coverity": _coverity_prompt(),
    "CheckpointCve": _checkpoint_cve_prompt(),
    "CheckpointSecret": _checkpoint_secret_prompt(),
    "CheckpointThreat": _checkpoint_threat_prompt(),
}


def build_system_prompt(sheet_name: str) -> str:
    return _SYSTEM_PROMPTS.get(
        sheet_name,
        f"You are a senior security engineer triaging {sheet_name} findings.\n" + _RESPONSE_FORMAT,
    )


# ── Core functions ─────────────────────────────────────────────────────────────

def load_priority_config(path: str) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return {str(k): str(v).lower() for k, v in data.items()}


def extract_project_code(wb: openpyxl.Workbook) -> str:
    """Extract ap\\d{4} from container image names. Checks container sheets first (most reliable)."""
    for sheet_name in ("CheckpointCve", "CheckpointSecret", "CheckpointThreat", "Blackduck", "Coverity"):
        if sheet_name not in wb.sheetnames:
            continue
        id_col_name = SHEET_ID_COL[sheet_name]
        ws = wb[sheet_name]
        headers = [c.value for c in next(ws.iter_rows(max_row=1))]
        if id_col_name not in headers:
            continue
        col_idx = headers.index(id_col_name)
        for row in ws.iter_rows(min_row=2, max_row=6, values_only=True):
            val = row[col_idx] if len(row) > col_idx else None
            if val:
                m = re.search(r'ap\d{4}', str(val))
                if m:
                    return m.group()
    return ""


def read_sheet(ws) -> list:
    """Read worksheet rows into dicts. Injects 'row_id' = openpyxl row number (2-based)."""
    rows = list(ws.iter_rows(values_only=True))
    if len(rows) < 2:
        return []
    headers = [str(h) if h is not None else f"col_{i}" for i, h in enumerate(rows[0])]
    result = []
    for row_idx, row in enumerate(rows[1:], start=2):
        d = dict(zip(headers, row))
        d["row_id"] = row_idx
        result.append(d)
    return result


def build_triage_payload(findings: list, sheet_name: str) -> list:
    """Return stripped payload — only relevant fields to control prompt token count."""
    fields = TRIAGE_FIELDS.get(sheet_name)
    if not fields:
        return findings
    return [{k: f.get(k) for k in fields} for f in findings]


def call_claude_triage(
    client: anthropic.Anthropic,
    sheet_name: str,
    chunk: list,
    project_priority: str,
) -> list:
    """Single Claude API call for one chunk. Returns list of triage dicts."""
    payload = build_triage_payload(chunk, sheet_name)
    priority_note = (
        "High priority project: maintain or escalate severity. "
        "Compensating controls must be specific and include a remediation timeline. "
        "Do not accept Critical or High findings."
        if project_priority == "high"
        else
        "Low priority project: accepted risk is permissible for Medium and Low findings "
        "when no public exploit exists and a fix is unavailable. Document the rationale."
    )
    user_msg = (
        f"Project priority: {project_priority}\n{priority_note}\n\n"
        f"Triage the following {sheet_name} findings and return the JSON array:\n\n"
        f"{json.dumps(payload, indent=2, default=str)}"
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        system=[{
            "type": "text",
            "text": build_system_prompt(sheet_name),
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": user_msg}],
    )
    _token_usage["input"] += response.usage.input_tokens
    _token_usage["output"] += response.usage.output_tokens
    _token_usage["calls"] += 1
    raw = response.content[0].text.strip()
    # Strip markdown fences if present
    raw = re.sub(r'^```(?:json)?\s*\n?', '', raw)
    raw = re.sub(r'\n?```\s*$', '', raw)
    return json.loads(raw.strip())


# ── Structural verifier (independent of Claude — see CLAUDE.md) ───────────────

def validate_triage_chunk(input_chunk: list, triage_output: list) -> list:
    """Return list of issue strings. Empty list = clean. Never calls the API."""
    issues = []
    output_map = {r.get("row_id"): r for r in triage_output}

    for finding in input_chunk:
        rid = finding["row_id"]
        result = output_map.get(rid)

        if result is None:
            issues.append(f"row_id {rid}: missing from triage output")
            continue

        sev = result.get("residual_severity", "")
        if sev not in VALID_SEVERITIES:
            issues.append(f"row_id {rid}: invalid residual_severity '{sev}'")

        ctrl = result.get("compensation_control", "")
        if not ctrl or len(ctrl.strip()) <= 10:
            issues.append(f"row_id {rid}: compensation_control is empty or too short")

    return issues


def _escalation_flags(input_chunk: list, triage_output: list) -> list:
    """Return row_ids where residual severity was escalated 2+ levels above original (human review only)."""
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    output_map = {r.get("row_id"): r for r in triage_output}
    flagged = []
    for finding in input_chunk:
        orig = str(finding.get("Severity") or finding.get("severity") or "").strip()
        result = output_map.get(finding["row_id"], {})
        residual = result.get("residual_severity", "")
        if orig in order and residual in order:
            if order[residual] - order[orig] >= 2:
                flagged.append(finding["row_id"])
    return flagged



def review_sheet(
    client: anthropic.Anthropic,
    sheet_name: str,
    findings: list,
    project_priority: str,
) -> list:
    """Reviewer agent for one sheet. Chunks → Claude → structural QC → bounded retry → merge."""
    chunks = [findings[i:i + CHUNK_SIZE] for i in range(0, len(findings), CHUNK_SIZE)]
    triage_map: dict = {}
    validation_failures: list = []
    escalation_flags: list = []

    for i, chunk in enumerate(chunks):
        # First attempt
        results = []
        try:
            results = call_claude_triage(client, sheet_name, chunk, project_priority)
        except Exception as e:
            log.warning(f"  {sheet_name} chunk {i + 1}/{len(chunks)} API error: {e}")

        issues = validate_triage_chunk(chunk, results)

        # Retry once: re-request only missing rows
        if issues:
            log.warning(f"  {sheet_name} chunk {i + 1}/{len(chunks)} validation issues, retrying missing rows: {issues[:3]}")
            missing_ids = {int(m.group(1)) for iss in issues if "missing" in iss for m in [re.match(r"row_id (\d+):", iss)] if m}
            if missing_ids:
                retry_chunk = [f for f in chunk if f["row_id"] in missing_ids]
                try:
                    retry_results = call_claude_triage(client, sheet_name, retry_chunk, project_priority)
                    existing = {r["row_id"]: r for r in results}
                    existing.update({r["row_id"]: r for r in retry_results})
                    results = list(existing.values())
                except Exception as e:
                    log.warning(f"  {sheet_name} chunk {i + 1} retry failed: {e}")
            issues = validate_triage_chunk(chunk, results)

        # Mark any still-failing rows as VALIDATION_FAILED
        if issues:
            log.warning(f"  {sheet_name} chunk {i + 1}/{len(chunks)} still has issues after retry: {issues}")
            failed_ids = set()
            for iss in issues:
                m = re.match(r"row_id (\d+):", iss)
                if m:
                    rid = int(m.group(1))
                    failed_ids.add(rid)
                    validation_failures.append(f"{sheet_name} row {rid}: {iss}")
            results = [r for r in results if r.get("row_id") not in failed_ids]
            results += [
                {"row_id": rid, "compensation_control": "VALIDATION_FAILED", "residual_severity": "Info"}
                for rid in failed_ids
            ]
            # Also add sentinels for rows completely absent from results
            covered = {r["row_id"] for r in results}
            for f in chunk:
                if f["row_id"] not in covered:
                    results.append({"row_id": f["row_id"], "compensation_control": "VALIDATION_FAILED", "residual_severity": "Info"})

        escalation_flags.extend(_escalation_flags(chunk, results))
        for r in results:
            triage_map[r["row_id"]] = r
        log.info(f"  {sheet_name} chunk {i + 1}/{len(chunks)} done ({len(chunk)} findings)")

    if validation_failures:
        log.warning(f"  {sheet_name}: {len(validation_failures)} rows marked VALIDATION_FAILED — human review required")
    if escalation_flags:
        log.warning(f"  {sheet_name}: {len(escalation_flags)} rows flagged for severity escalation review (row_ids: {escalation_flags})")

    for f in findings:
        t = triage_map.get(f["row_id"], {})
        f["compensation_control"] = t.get("compensation_control", "")
        f["residual_severity"] = t.get("residual_severity", "")
        f["_validation_failed"] = t.get("compensation_control") == "VALIDATION_FAILED"
        f["_escalation_flagged"] = f["row_id"] in escalation_flags

    return findings


def write_triage_columns(ws, findings: list) -> None:
    """Write Asset Importance, Compensation Control, Residual Severity back to worksheet."""
    # Case-insensitive header lookup
    headers = {str(cell.value).lower(): cell.column for cell in ws[1] if cell.value}
    ai_col = headers.get("asset importance")
    cc_col = headers.get("compensation control")
    rs_col = headers.get("residual severity")

    for f in findings:
        row_id = f["row_id"]
        if ai_col:
            ws.cell(row=row_id, column=ai_col).value = f.get("Asset Importance", "")
        if cc_col:
            ws.cell(row=row_id, column=cc_col).value = f.get("compensation_control", "")
        if rs_col:
            ws.cell(row=row_id, column=rs_col).value = f.get("residual_severity", "")


def generate_summary(client: anthropic.Anthropic, all_triaged: dict) -> str:
    """Summary agent — one Claude call, returns markdown executive summary."""
    summary_data = {}
    total_validation_failures = 0
    total_escalation_flags = 0

    for sheet_name, findings in all_triaged.items():
        sev_dist = dict(Counter(f.get("residual_severity") or "Pending" for f in findings))
        high_crit = [
            {
                "issue": (
                    f.get("CVE Name") or f.get("Issue Name") or
                    f.get("name") or f.get("threatType") or "Unknown"
                ),
                "residual_severity": f.get("residual_severity", ""),
                "compensation_control": f.get("compensation_control", ""),
            }
            for f in findings
            if f.get("residual_severity") in ("Critical", "High")
        ][:10]
        failed = sum(1 for f in findings if f.get("_validation_failed"))
        flagged = sum(1 for f in findings if f.get("_escalation_flagged"))
        total_validation_failures += failed
        total_escalation_flags += flagged
        summary_data[sheet_name] = {
            "total_findings": len(findings),
            "severity_distribution": sev_dist,
            "critical_and_high_samples": high_crit,
            "validation_failed_rows": failed,
            "escalation_flagged_rows": flagged,
        }

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=[{
            "role": "user",
            "content": (
                "You are a security engineering manager writing an executive summary of a CI/CD security scan report.\n\n"
                "Here are the triaged findings organized by scanner:\n"
                f"{json.dumps(summary_data, indent=2)}\n\n"
                "Write a markdown report with exactly these four sections:\n"
                "## Overview\n"
                "## Critical and High Findings\n"
                "## Top Risks by Scan Type\n"
                "## Recommended Actions\n\n"
                "Be concise and actionable. Target audience: engineering director, not a security analyst. "
                "Use bullet points. Avoid jargon."
                + (
                    f"\n\nNOTE: {total_validation_failures} rows could not be automatically triaged "
                    f"(marked VALIDATION_FAILED) and require human review. "
                    f"Mention this in the Overview section."
                    if total_validation_failures else ""
                )
                + (
                    f"\n\nNOTE: {total_escalation_flags} rows were flagged for unexpected severity escalation "
                    f"and should be reviewed by a security engineer."
                    if total_escalation_flags else ""
                )
            ),
        }],
    )
    _token_usage["input"] += response.usage.input_tokens
    _token_usage["output"] += response.usage.output_tokens
    _token_usage["calls"] += 1
    return response.content[0].text


# ── Orchestrator ───────────────────────────────────────────────────────────────

def run(xlsx_path: str, config_path: str, output_xlsx: str, output_md: str, project_override: str = "") -> None:
    priority_config = load_priority_config(config_path)
    wb = openpyxl.load_workbook(xlsx_path)

    project_code = project_override or extract_project_code(wb)
    if not project_code:
        log.warning("Could not extract project code from report. Defaulting to low priority.")
    elif project_code not in priority_config:
        log.warning(f"Project code '{project_code}' not in config. Defaulting to low priority.")

    project_priority = priority_config.get(project_code, "low")
    asset_importance = "High" if project_priority == "high" else "Low"
    log.info(f"Project: {project_code or 'unknown'} | Priority: {project_priority} | Asset Importance: {asset_importance}")

    base_url = os.getenv("REVIEWER_BASE_URL")
    client = anthropic.Anthropic(
        **({"base_url": base_url} if base_url else {}),
        # Gateway sits behind Cloudflare which blocks the default httpx UA
        **({"default_headers": {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}} if base_url else {}),
    )
    if base_url:
        log.info(f"Using gateway: {base_url}")

    sheets_data = {}
    for sheet_name in SHEET_ID_COL:
        if sheet_name not in wb.sheetnames:
            continue
        findings = read_sheet(wb[sheet_name])
        if not findings:
            log.info(f"{sheet_name}: empty, skipping")
            continue
        for f in findings:
            f["Asset Importance"] = asset_importance
        sheets_data[sheet_name] = findings
        log.info(f"{sheet_name}: {len(findings)} findings")

    if not sheets_data:
        log.error("No supported sheets found in workbook.")
        sys.exit(1)

    triaged = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            sheet_name: ex.submit(review_sheet, client, sheet_name, findings, project_priority)
            for sheet_name, findings in sheets_data.items()
        }
        for sheet_name, future in futures.items():
            try:
                triaged[sheet_name] = future.result()
                log.info(f"{sheet_name}: triage complete")
            except Exception as e:
                log.error(f"{sheet_name}: triage failed entirely: {e}")
                triaged[sheet_name] = sheets_data[sheet_name]

    for sheet_name, findings in triaged.items():
        write_triage_columns(wb[sheet_name], findings)

    wb.save(output_xlsx)
    log.info(f"Saved annotated report: {output_xlsx}")

    summary = generate_summary(client, triaged)
    Path(output_md).write_text(summary, encoding="utf-8")
    log.info(f"Saved summary: {output_md}")
    log.info(
        f"Token usage — input: {_token_usage['input']:,}  "
        f"output: {_token_usage['output']:,}  "
        f"total: {_token_usage['input'] + _token_usage['output']:,}  "
        f"({_token_usage['calls']} API calls)"
    )


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Triage DSO security scan reports using Claude LLM")
    p.add_argument("--input", required=True, help="Input XLSX report path")
    p.add_argument("--config", required=True, help="Priority config YAML path")
    p.add_argument("--output-xlsx", help="Output XLSX path (default: <input>_triaged.xlsx)")
    p.add_argument("--output-md", help="Output markdown summary path (default: <input>_summary.md)")
    p.add_argument("--project", default="", help="Override project code (e.g. ap2065)")
    args = p.parse_args()

    inp = Path(args.input)
    out_xlsx = args.output_xlsx or str(inp.with_name(inp.stem + "_triaged.xlsx"))
    out_md = args.output_md or str(inp.with_name(inp.stem + "_summary.md"))

    run(str(inp), args.config, out_xlsx, out_md, args.project)


if __name__ == "__main__":
    main()
