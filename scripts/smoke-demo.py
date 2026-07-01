#!/usr/bin/env python3
"""Run the local MVP demo acceptance smoke test."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import openpyxl

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from demo_agent import DemoAgentHandler  # noqa: E402


def request_json(base_url: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
    data = None
    headers = {}
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def request_text(base_url: str, path: str) -> str:
    with urllib.request.urlopen(f"{base_url}{path}", timeout=5) as response:
        return response.read().decode("utf-8")


def request_bytes(base_url: str, path: str) -> bytes:
    with urllib.request.urlopen(f"{base_url}{path}", timeout=5) as response:
        return response.read()


def wait_for_health(base_url: str) -> None:
    deadline = time.monotonic() + 5
    last_error = "not started"
    while time.monotonic() < deadline:
        try:
            data = request_json(base_url, "/healthz")
            if data == {"status": "ok"}:
                return
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.1)
    raise RuntimeError(f"demo agent did not become healthy: {last_error}")


def assert_contains(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise RuntimeError(f"{label} missing expected text: {needle}")


def run_smoke() -> str:
    with tempfile.TemporaryDirectory(prefix="dso-demo-smoke-") as temp_dir:
        server = ThreadingHTTPServer(("127.0.0.1", 0), DemoAgentHandler)
        server.data_dir = Path(temp_dir)  # type: ignore[attr-defined]
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            wait_for_health(base_url)

            ui_html = request_text(base_url, "/ui/index.html")
            assert_contains(ui_html, "DSO Report Reviewer - Operator UI", "operator UI")
            assert_contains(ui_html, "command-box", "operator UI")
            assert_contains(ui_html, "/demo/reset", "operator UI")

            runbook_html = request_text(base_url, "/docs/MVP-DEMO-RUNBOOK.html")
            assert_contains(runbook_html, "MVP Demo Runbook", "runbook")
            assert_contains(runbook_html, "uv run pytest", "runbook")

            reset = request_json(base_url, "/demo/reset", {})
            if not isinstance(reset, dict) or reset.get("finding_count") != 4:
                raise RuntimeError(f"unexpected reset response: {reset}")

            findings = request_json(base_url, "/jobs/build-92619/findings")
            if not isinstance(findings, list) or len(findings) != 4:
                raise RuntimeError("expected four demo findings")
            row_42 = next((item for item in findings if item.get("row_id") == 42), None)
            if not row_42 or not row_42.get("remediation_commands"):
                raise RuntimeError("row 42 missing remediation commands")

            request_json(
                base_url,
                "/jobs/build-92619/reviews",
                {
                    "row_id": 18,
                    "review_status": "approved",
                    "reviewer_note": "Approved after confirming credential rotation plan.",
                },
            )

            summary = request_text(base_url, "/jobs/build-92619/outputs/summary.md")
            assert_contains(summary, "Maven dependency pin", "summary")
            assert_contains(summary, "Row 18: approved", "summary")
            assert_contains(summary, "Row 33: Validation failed", "summary")

            xlsx_bytes = request_bytes(base_url, "/jobs/build-92619/outputs/annotated.xlsx")
            workbook_path = Path(temp_dir) / "downloaded.xlsx"
            workbook_path.write_bytes(xlsx_bytes)
            workbook = openpyxl.load_workbook(workbook_path)
            worksheet = workbook["Reviewed Findings"]
            headers = [cell.value for cell in worksheet[1]]
            if "Technical Commands" not in headers:
                raise RuntimeError("downloaded XLSX missing Technical Commands column")
            xlsx_row_18 = next(row for row in worksheet.iter_rows(values_only=True) if row[1] == 18)
            if xlsx_row_18[10] != "approved":
                raise RuntimeError("downloaded XLSX did not persist row 18 approval")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return "MVP demo smoke passed"


def main() -> int:
    try:
        print(run_smoke())
        return 0
    except Exception as exc:
        print(f"MVP demo smoke failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
