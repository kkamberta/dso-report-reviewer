#!/usr/bin/env python3
"""Demo HTTP agent for DSO Report Reviewer.

This is intentionally deterministic. It demonstrates the webhook/container flow
without calling an LLM or external scanner APIs.
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import openpyxl

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
log = logging.getLogger(__name__)

ROOT = Path(__file__).parent
DEFAULT_DATA_DIR = ROOT / "demo-jobs"
DEFAULT_DEMO_PAYLOAD = {
    "job_id": "build-92619",
    "project": "ap2065",
    "priority": "high",
    "scanner": "mixed",
    "artifact_url": "https://ci.example/artifacts/report.xlsx",
}


def static_path(path: str) -> Path:
    if path in {"/", "/customer-pitch.html"}:
        return ROOT / "customer-pitch.html"
    if path == "/ui/index.html":
        return ROOT / "ui" / "index.html"
    if path == "/docs/MVP-DEMO-RUNBOOK.html":
        return ROOT / "docs" / "MVP-DEMO-RUNBOOK.html"
    return ROOT / path.lstrip("/")


@dataclass
class DemoJob:
    job_id: str
    project: str
    priority: str
    scanner: str
    artifact_url: str
    status: str = "completed"
    output_xlsx: str = ""
    output_md: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def human_review_required(self) -> bool:
        return any(f["review_status"] == "pending" for f in self.findings)

    @property
    def validation_failed_rows(self) -> int:
        return sum(1 for f in self.findings if f["flag"] == "Validation failed")

    @property
    def severity_review_rows(self) -> int:
        return sum(1 for f in self.findings if f["flag"] == "Severity changed")

    def as_status(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "project": self.project,
            "priority": self.priority,
            "scanner": self.scanner,
            "artifact_url": self.artifact_url,
            "status": self.status,
            "output_xlsx": self.output_xlsx,
            "output_md": self.output_md,
            "human_review_required": self.human_review_required,
            "validation_failed_rows": self.validation_failed_rows,
            "severity_review_rows": self.severity_review_rows,
            "finding_count": len(self.findings),
        }


JOBS: dict[str, DemoJob] = {}


def demo_findings(project: str, priority: str) -> list[dict[str, Any]]:
    asset = "High" if priority == "high" else "Low"
    return [
        {
            "scanner": "Black Duck",
            "row_id": 42,
            "finding": "Apache Tomcat CVE-2025-66614",
            "component": "tomcat-embed-core 10.1.20",
            "original_severity": "Critical",
            "residual_severity": "Critical",
            "asset_importance": asset,
            "compensation_control": "Upgrade tomcat-embed-core to 10.1.56. Keep external Tomcat endpoints restricted by network ACL until the upgrade is deployed.",
            "remediation_commands": [
                {
                    "label": "Maven dependency pin",
                    "command": "mvn versions:use-dep-version -Dincludes=org.apache.tomcat.embed:tomcat-embed-core -DdepVersion=10.1.56 -DforceVersion=true",
                },
                {
                    "label": "Gradle dependency pin",
                    "command": "./gradlew dependencies --write-locks",
                },
            ],
            "flag": "None",
            "review_status": "approved",
            "reviewer_note": "Demo baseline: no additional approval required.",
        },
        {
            "scanner": "Checkpoint CVE",
            "row_id": 77,
            "finding": "OpenSSL package CVE-2025-15467",
            "component": f"{project}/payments-api:build",
            "original_severity": "High",
            "residual_severity": "High",
            "asset_importance": asset,
            "compensation_control": "Rebuild the container image from a patched base image that includes fixed libssl and libcrypto packages.",
            "remediation_commands": [
                {
                    "label": "Alpine package refresh",
                    "command": "apk upgrade --no-cache libssl3 libcrypto3",
                },
            ],
            "flag": "None",
            "review_status": "approved",
            "reviewer_note": "Demo baseline: container rebuild path is accepted.",
        },
        {
            "scanner": "Checkpoint Secret",
            "row_id": 18,
            "finding": "Production secret in application-prod.yml",
            "component": "Spring Boot JAR",
            "original_severity": "High",
            "residual_severity": "Critical",
            "asset_importance": asset,
            "compensation_control": "Confirm whether values are live credentials. If confirmed, rotate within 24 hours and replace file-based secrets with runtime secret manager injection.",
            "remediation_commands": [],
            "flag": "Severity changed",
            "review_status": "pending",
            "reviewer_note": "",
        },
        {
            "scanner": "Coverity",
            "row_id": 33,
            "finding": "Missing remediation text from scanner output",
            "component": "src/auth/session.py",
            "original_severity": "Medium",
            "residual_severity": "Info",
            "asset_importance": asset,
            "compensation_control": "VALIDATION_FAILED",
            "remediation_commands": [],
            "flag": "Validation failed",
            "review_status": "pending",
            "reviewer_note": "",
        },
    ]


def create_demo_job(payload: dict[str, Any], data_dir: Path = DEFAULT_DATA_DIR) -> DemoJob:
    job_id = str(payload.get("job_id") or payload.get("build_id") or "build-92619")
    project = str(payload.get("project") or "ap2065")
    priority = str(payload.get("priority") or "high").lower()
    scanner = str(payload.get("scanner") or "mixed")
    artifact_url = str(payload.get("artifact_url") or "demo://sample-report")
    findings = demo_findings(project, priority)

    job_dir = data_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    output_xlsx = job_dir / "annotated.xlsx"
    output_md = job_dir / "summary.md"
    write_annotated_xlsx(output_xlsx, findings)
    write_summary(output_md, job_id, project, priority, findings)

    job = DemoJob(
        job_id=job_id,
        project=project,
        priority=priority,
        scanner=scanner,
        artifact_url=artifact_url,
        output_xlsx=str(output_xlsx),
        output_md=str(output_md),
        findings=findings,
    )
    JOBS[job_id] = job
    return job


def reset_demo(data_dir: Path = DEFAULT_DATA_DIR) -> DemoJob:
    """Reset the fixed MVP demo job to its clean pre-approval state."""
    return create_demo_job(DEFAULT_DEMO_PAYLOAD, data_dir)


def write_annotated_xlsx(path: Path, findings: list[dict[str, Any]]) -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Reviewed Findings"
    headers = [
        "Scanner",
        "Row ID",
        "Finding",
        "Component",
        "Original Severity",
        "Residual Severity",
        "Asset Importance",
        "Compensation Control",
        "Technical Commands",
        "Flag",
        "Review Status",
        "Reviewer Note",
    ]
    ws.append(headers)
    for finding in findings:
        ws.append([
            finding["scanner"],
            finding["row_id"],
            finding["finding"],
            finding["component"],
            finding["original_severity"],
            finding["residual_severity"],
            finding["asset_importance"],
            finding["compensation_control"],
            format_remediation_commands(finding),
            finding["flag"],
            finding["review_status"],
            finding.get("reviewer_note", ""),
        ])
    wb.save(path)


def write_summary(path: Path, job_id: str, project: str, priority: str, findings: list[dict[str, Any]]) -> None:
    review_rows = [f for f in findings if f["review_status"] == "pending"]
    approved_rows = [f for f in findings if f["review_status"] in {"approved", "override"}]
    critical_high = [f for f in findings if f["residual_severity"] in {"Critical", "High"}]
    text = (
        f"# DSO Report Reviewer Demo Summary\n\n"
        f"## Overview\n"
        f"Job `{job_id}` reviewed `{project}` as `{priority}` priority. "
        f"{len(findings)} demo findings were processed with {len(review_rows)} rows requiring human review.\n\n"
        f"## Critical and High Findings\n"
        + "\n".join(
            f"- {f['residual_severity']}: {f['finding']} - {f['compensation_control']}"
            f"{format_summary_commands(f)}"
            for f in critical_high
        )
        + "\n\n## Human Review Queue\n"
        + ("\n".join(f"- Row {f['row_id']}: {f['flag']} - {f['finding']}" for f in review_rows) or "- No pending review rows.")
        + "\n\n## Approved Review Decisions\n"
        + ("\n".join(
            f"- Row {f['row_id']}: {f['review_status']} - {f['finding']} - {f.get('reviewer_note') or 'No reviewer note.'}"
            for f in approved_rows
        ) or "- No approved decisions yet.")
        + "\n"
    )
    path.write_text(text, encoding="utf-8")


def format_remediation_commands(finding: dict[str, Any]) -> str:
    commands = finding.get("remediation_commands") or []
    return "\n".join(
        f"{item.get('label', 'Command')}: {item.get('command', '')}"
        for item in commands
        if item.get("command")
    )


def format_summary_commands(finding: dict[str, Any]) -> str:
    commands = format_remediation_commands(finding)
    if not commands:
        return ""
    return f"\n\n  Technical command:\n\n  ```bash\n  {commands.replace(chr(10), chr(10) + '  ')}\n  ```"


def apply_review_decision(job: DemoJob, payload: dict[str, Any]) -> dict[str, Any] | str:
    row_id = payload.get("row_id")
    if row_id is None:
        return "row_id is required"
    try:
        row_id = int(row_id)
    except (TypeError, ValueError):
        return "row_id must be an integer"

    review_status = str(payload.get("review_status") or "").strip().lower()
    if review_status not in {"pending", "approved", "override"}:
        return "review_status must be pending, approved, or override"

    finding = next((f for f in job.findings if int(f["row_id"]) == row_id), None)
    if finding is None:
        return f"row_id {row_id} not found"

    if payload.get("residual_severity"):
        finding["residual_severity"] = str(payload["residual_severity"])
    if payload.get("compensation_control"):
        finding["compensation_control"] = str(payload["compensation_control"])
    finding["review_status"] = review_status
    finding["reviewer_note"] = str(payload.get("reviewer_note") or "")

    write_annotated_xlsx(Path(job.output_xlsx), job.findings)
    write_summary(Path(job.output_md), job.job_id, job.project, job.priority, job.findings)
    return finding


class DemoAgentHandler(BaseHTTPRequestHandler):
    server_version = "DSODemoAgent/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/healthz":
            body = b'{"status":"ok"}'
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        if path in {"/", "/customer-pitch.html", "/ui/index.html", "/docs/MVP-DEMO-RUNBOOK.html"}:
            target = static_path(path)
            if target.exists():
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(target.stat().st_size))
                self.end_headers()
                return
        self._send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _send_json(self, status: int, data: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> dict[str, Any] | str:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw)
            if not isinstance(data, dict):
                return "JSON body must be an object"
            return data
        except Exception as exc:
            return f"Invalid JSON body: {exc}"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/jobs":
            self._send_json(HTTPStatus.OK, [job.as_status() for job in JOBS.values()])
            return
        if path.startswith("/jobs/"):
            self._handle_job_get(path)
            return
        if path in {"/", "/customer-pitch.html", "/ui/index.html", "/docs/MVP-DEMO-RUNBOOK.html"}:
            self._send_static(path)
            return
        self._send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/demo/reset":
            try:
                job = reset_demo(self.server.data_dir)  # type: ignore[attr-defined]
                self._send_json(HTTPStatus.OK, job.as_status())
            except Exception as exc:
                self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Failed to reset demo: {exc}")
            return
        if parsed.path.startswith("/jobs/") and parsed.path.endswith("/reviews"):
            self._handle_review_post(parsed.path)
            return
        if parsed.path not in {"/jobs", "/webhooks/scan-finished"}:
            self._send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        data = self._read_json()
        if isinstance(data, str):
            self._send_error(HTTPStatus.BAD_REQUEST, data)
            return
        try:
            job = create_demo_job(data, self.server.data_dir)  # type: ignore[attr-defined]
            self._send_json(HTTPStatus.CREATED, job.as_status())
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Failed to create demo job: {exc}")

    def _handle_review_post(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) != 3 or parts[0] != "jobs" or parts[2] != "reviews":
            self._send_error(HTTPStatus.NOT_FOUND, "Unknown review endpoint")
            return
        job = JOBS.get(parts[1])
        if job is None:
            self._send_error(HTTPStatus.NOT_FOUND, "Unknown job")
            return
        data = self._read_json()
        if isinstance(data, str):
            self._send_error(HTTPStatus.BAD_REQUEST, data)
            return
        result = apply_review_decision(job, data)
        if isinstance(result, str):
            self._send_error(HTTPStatus.BAD_REQUEST, result)
            return
        self._send_json(HTTPStatus.OK, {"job": job.as_status(), "finding": result})

    def _handle_job_get(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            self._send_error(HTTPStatus.NOT_FOUND, "Missing job id")
            return
        job = JOBS.get(parts[1])
        if job is None:
            self._send_error(HTTPStatus.NOT_FOUND, "Unknown job")
            return
        if len(parts) == 2:
            self._send_json(HTTPStatus.OK, job.as_status())
            return
        if parts[2:] == ["findings"]:
            self._send_json(HTTPStatus.OK, job.findings)
            return
        if parts[2:] == ["outputs", "summary.md"]:
            self._send_file(Path(job.output_md), "text/markdown; charset=utf-8")
            return
        if parts[2:] == ["outputs", "annotated.xlsx"]:
            self._send_file(Path(job.output_xlsx), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            return
        self._send_error(HTTPStatus.NOT_FOUND, "Unknown job endpoint")

    def _send_static(self, path: str) -> None:
        target = static_path(path)
        self._send_file(target, "text/html; charset=utf-8")

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self._send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str, port: int, data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((host, port), DemoAgentHandler)
    server.data_dir = data_dir  # type: ignore[attr-defined]
    log.info("Demo agent listening on http://%s:%s", host, port)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the DSO Report Reviewer demo HTTP agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    args = parser.parse_args()
    run_server(args.host, args.port, Path(args.data_dir))


if __name__ == "__main__":
    main()
