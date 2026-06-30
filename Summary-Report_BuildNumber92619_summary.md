# CI/CD Security Scan Executive Summary

## Overview

The latest CI/CD security scan across four tools — **Black Duck** (open-source dependencies), **Coverity** (static code analysis), **Checkpoint CVE** (container image vulnerabilities), and **Checkpoint Secret** (secrets detection) — identified **361 total findings**, including **56 Critical** and **249 High** severity issues. All findings have been triaged and assigned remediation timelines.

> ⚠️ **32 findings were flagged for unexpected severity escalation and require review by a security engineer before results are considered final.**

| Scanner | Total | Critical | High |
|---|---|---|---|
| Black Duck | 238 | 53 | 185 |
| Coverity | 25 | 0 | 25 |
| Checkpoint CVE | 86 | 3 | 31 |
| Checkpoint Secret | 12 | 0 | 8 |
| **Total** | **361** | **56** | **249** |

---

## Critical and High Findings

### 🔴 Critical — Immediate Action Required (within 5–14 days)

- **Apache Tomcat vulnerabilities** (Black Duck): Two Critical CVEs (CVE-2025-66614, CVE-2026-29145) with CVSS scores of 9.1 — upgrade to Tomcat 10.1.56 required within **14 days**.
- **Container image — OpenSSL/libssl** (Checkpoint CVE): CVE-2025-15467 is unscored and treated as Critical per policy. Affects both `libcrypto3` and `libssl3`. Rebuild the container image within **5 business days**.
- **Secrets bundled in the container image** (Checkpoint Secret): Potential production credentials found inside the deployed Spring Boot JAR (`application-prod.yml`, `application.yml`). If confirmed real, rotate and remove within **24 hours**.

### 🟠 High — Remediate Within 30 Days (or sooner as noted)

- **Apache Tomcat** (Black Duck): 185 High-severity CVEs, all resolved by the same Tomcat 10.1.56 upgrade. Restrict external access to Tomcat endpoints via network ACL as an interim control.
- **Hard-coded secrets in source code** (Coverity): 24 instances of credentials committed directly to config files (`application.yml`, `application-sit.yml`, `application-dev.yml`). Rotate all exposed credentials and migrate to a secrets manager within **5 business days**.
- **Container running as root** (Coverity): Application container runs with root privileges. Add a non-root `USER` directive to the Dockerfile within **5 business days**.
- **Additional container CVEs** (Checkpoint CVE): 31 High CVEs in `libcrypto3`/`libssl3` — resolved by the same container image rebuild noted above.
- **Secrets in source config files** (Checkpoint Secret): 8 High-severity findings of secrets and passwords in YAML config files bundled in the JAR. Investigate, rotate if real, and inject via secrets manager within **24 hours** if confirmed.

---

## Top Risks by Scan Type

- **Black Duck — Outdated Apache Tomcat**: A single dependency upgrade to Tomcat 10.1.56 resolves all 238 findings. The concentration of 53 Critical vulnerabilities in one component represents the highest volume risk in this scan. **Priority: upgrade Tomcat.**

- **Coverity — Secrets in source code**: Credentials are committed directly to version-controlled config files and are likely present in the git history even after removal. This is a developer practice problem, not just a one-time fix. **Priority: rotate credentials now, adopt a secrets manager, and enforce pre-commit secret scanning.**

- **Checkpoint CVE — Stale container base image**: The container image contains outdated OpenSSL libraries with known exploits. A single base image rebuild resolves the majority of these findings. **Priority: rebuild and redeploy the container image this sprint.**

- **Checkpoint Secret — Production credentials in deployed artifacts**: Secrets found inside the running container image (`application-prod.yml`) are the highest-risk Checkpoint findings — they are accessible to anyone who can pull or inspect the image. **Priority: confirm, rotate, and remove within 24 hours.**

---

## Recommended Actions

**This sprint (within 5 business days):**
- [ ] Rebuild the container image with updated `libcrypto3` and `libssl3` (≥ 3.3.6-r0) to resolve Checkpoint CVE Critical findings
- [ ] Investigate all 8 High-severity Checkpoint Secret findings — rotate any confirmed credentials within 24 hours
- [ ] Remove all hard-coded secrets from `application.yml`, `application-sit.yml`, and `application-dev.yml`; rotate exposed credentials and replace with secrets manager references (HashiCorp Vault, AWS Secrets Manager, or equivalent)
- [ ] Update the Dockerfile to run the container as a non-root user
- [ ] Apply network ACLs to restrict external access to Tomcat endpoints as an interim control pending the upgrade
- [ ] Assign a security engineer to **review 32 escalation-flagged findings** and confirm or adjust severity ratings

**Within 14 days:**
- [ ] Upgrade Apache Tomcat to 10.1.56 to resolve the two Critical CVEs (CVE-2025-66614, CVE-2026-29145)

**Within 30 days:**
- [ ] Confirm Tomcat 10.1.56 upgrade is complete and verified, closing all 238 Black Duck findings

**Structural / process improvements:**
- [ ] Enforce pre-commit secret scanning in the developer workflow to prevent credential commits from reaching the repository
- [ ] Add a CI pipeline gate that blocks builds if a container runs as root
- [ ] Establish a recurring base image refresh cadence to prevent OS-level CVE accumulation