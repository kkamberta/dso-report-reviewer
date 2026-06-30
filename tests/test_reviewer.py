"""Unit tests for reviewer.py — mocked at the Anthropic SDK boundary."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import openpyxl
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from reviewer import (
    CHUNK_SIZE,
    _escalation_flags,
    build_system_prompt,
    build_triage_payload,
    call_claude_triage,
    extract_project_code,
    generate_summary,
    load_priority_config,
    read_sheet,
    review_sheet,
    validate_triage_chunk,
    write_triage_columns,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_workbook(sheets: dict) -> openpyxl.Workbook:
    """Build an in-memory workbook. sheets = {sheet_name: [header_row, row2, row3, ...]}"""
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for name, rows in sheets.items():
        ws = wb.create_sheet(name)
        for row in rows:
            ws.append(row)
    return wb


def _mock_response(data: list) -> MagicMock:
    """Build a fake anthropic Messages response containing JSON data."""
    msg = MagicMock()
    msg.content = [MagicMock(text=json.dumps(data))]
    return msg


# ── extract_project_code ──────────────────────────────────────────────────────

def test_extract_project_code_from_checkpoint_cve():
    wb = _make_workbook({
        "CheckpointCve": [
            ["No.", "ImageName", "name"],
            [1, "harbordev.se.scb.co.th/ap2065-cbproduct/scbcbs-api:v2.7.25", "CVE-2023-1234"],
        ]
    })
    assert extract_project_code(wb) == "ap2065"


def test_extract_project_code_returns_empty_when_not_found():
    wb = _make_workbook({
        "Coverity": [
            ["No.", "Path Source"],
            [1, "/src/main/java/App.java"],
        ]
    })
    assert extract_project_code(wb) == ""


def test_extract_project_code_falls_back_to_blackduck():
    wb = _make_workbook({
        "Blackduck": [
            ["No.", "Libraries", "Archive Context and Path"],
            [1, "spring-core", "ap2252-ddg/pom.xml/-maven/org.springframework:spring-core:5.3.0"],
        ]
    })
    assert extract_project_code(wb) == "ap2252"


# ── read_sheet ────────────────────────────────────────────────────────────────

def test_read_sheet_injects_row_id():
    wb = _make_workbook({
        "Blackduck": [
            ["Libraries", "Version", "Severity"],
            ["lodash", "4.17.20", "High"],
            ["axios", "0.21.0", "Medium"],
            ["moment", "2.29.1", "Low"],
        ]
    })
    rows = read_sheet(wb["Blackduck"])
    assert len(rows) == 3
    assert rows[0]["row_id"] == 2
    assert rows[1]["row_id"] == 3
    assert rows[2]["row_id"] == 4
    assert rows[0]["Libraries"] == "lodash"


def test_read_sheet_empty():
    wb = _make_workbook({"Blackduck": [["Libraries", "Version"]]})
    assert read_sheet(wb["Blackduck"]) == []


# ── build_system_prompt ────────────────────────────────────────────────────────

_PROMPT_KEYWORDS = {
    "Blackduck": "SCA",
    "Coverity": "SAST",
    "CheckpointCve": "CVE",
    "CheckpointSecret": "secret",
    "CheckpointThreat": "malware",
}


@pytest.mark.parametrize("sheet_name", ["Blackduck", "Coverity", "CheckpointCve", "CheckpointSecret", "CheckpointThreat"])
def test_build_system_prompt_contains_domain_keyword(sheet_name):
    prompt = build_system_prompt(sheet_name)
    keyword = _PROMPT_KEYWORDS[sheet_name]
    assert keyword.lower() in prompt.lower(), f"{sheet_name} prompt missing keyword '{keyword}'"


@pytest.mark.parametrize("sheet_name", ["Blackduck", "Coverity", "CheckpointCve", "CheckpointSecret", "CheckpointThreat"])
def test_build_system_prompt_long_enough_for_caching(sheet_name):
    # Anthropic requires >= 1024 tokens; rough proxy: >= 3000 characters (~750 words)
    prompt = build_system_prompt(sheet_name)
    assert len(prompt) >= 3000, f"{sheet_name} prompt too short: {len(prompt)} chars"


# ── load_priority_config ──────────────────────────────────────────────────────

def test_load_priority_config(tmp_path):
    cfg = tmp_path / "priority.yaml"
    cfg.write_text("ap2065: high\nap2252: low\n")
    result = load_priority_config(str(cfg))
    assert result == {"ap2065": "high", "ap2252": "low"}


def test_load_priority_config_missing_file():
    with pytest.raises(FileNotFoundError):
        load_priority_config("/nonexistent/priority.yaml")


# ── call_claude_triage ────────────────────────────────────────────────────────

def test_call_claude_triage_parses_response():
    triage_data = [
        {"row_id": 2, "compensation_control": "Upgrade lodash to 4.17.21.", "residual_severity": "High"},
    ]
    chunk = [{"row_id": 2, "Libraries": "lodash", "CVSS Score": 9.8, "Asset Importance": "High"}]
    with patch("reviewer.anthropic.Anthropic") as MockClient:
        client = MockClient()
        client.messages.create.return_value = _mock_response(triage_data)
        result = call_claude_triage(client, "Blackduck", chunk, "high")
    assert result == triage_data


def test_call_claude_triage_strips_markdown_fence():
    triage_data = [
        {"row_id": 3, "compensation_control": "Rebuild base image.", "residual_severity": "Critical"},
    ]
    fenced = f"```json\n{json.dumps(triage_data)}\n```"
    chunk = [{"row_id": 3, "name": "CVE-2025-1234", "baseScore": 9.8, "Asset Importance": "Low"}]
    with patch("reviewer.anthropic.Anthropic") as MockClient:
        client = MockClient()
        client.messages.create.return_value = MagicMock(content=[MagicMock(text=fenced)])
        result = call_claude_triage(client, "CheckpointCve", chunk, "low")
    assert result == triage_data


# ── review_sheet ──────────────────────────────────────────────────────────────

def test_review_sheet_chunks_correctly():
    findings = [{"row_id": i + 2, "Libraries": f"lib{i}", "Asset Importance": "Low"} for i in range(110)]
    triage_template = lambda chunk: [
        {"row_id": f["row_id"], "compensation_control": "Upgrade to latest version.", "residual_severity": "Low"}
        for f in chunk
    ]
    call_count = []
    with patch("reviewer.call_claude_triage") as mock_triage:
        mock_triage.side_effect = lambda client, sheet, chunk, priority: (
            call_count.append(len(chunk)) or triage_template(chunk)
        )
        result = review_sheet(MagicMock(), "Blackduck", findings, "low")

    assert len(call_count) == 3  # 50 + 50 + 10
    assert call_count == [50, 50, 10]
    assert len(result) == 110
    assert all(f["compensation_control"] == "Upgrade to latest version." for f in result)


def test_review_sheet_chunk_failure_partial():
    """Second chunk always fails — first 50 triaged ok, rest get VALIDATION_FAILED, no exception raised."""
    findings = [{"row_id": i + 2, "Libraries": f"lib{i}", "Asset Importance": "Low"} for i in range(100)]

    call_num = [0]
    def side_effect(client, sheet, chunk, priority):
        call_num[0] += 1
        if call_num[0] >= 2:  # all calls for chunk 2 (including retry) raise
            raise RuntimeError("API timeout")
        return [
            {"row_id": f["row_id"], "compensation_control": "Upgrade to latest version.", "residual_severity": "Low"}
            for f in chunk
        ]

    with patch("reviewer.call_claude_triage", side_effect=side_effect):
        result = review_sheet(MagicMock(), "Blackduck", findings, "low")

    assert len(result) == 100
    first_50 = result[:50]
    second_50 = result[50:]
    assert all(f["compensation_control"] == "Upgrade to latest version." for f in first_50)
    # Failed rows get the VALIDATION_FAILED sentinel, not silent empty strings
    assert all(f["compensation_control"] == "VALIDATION_FAILED" for f in second_50)


# ── write_triage_columns ──────────────────────────────────────────────────────

def test_write_triage_columns_roundtrip():
    wb = _make_workbook({
        "Blackduck": [
            ["No.", "Severity", "Asset Importance", "Compensation Control", "Residual Severity"],
            [1, "High", None, None, None],
            [2, "Medium", None, None, None],
            [3, "Low", None, None, None],
        ]
    })
    findings = [
        {"row_id": 2, "Asset Importance": "High", "compensation_control": "Upgrade to 4.17.21.", "residual_severity": "High"},
        {"row_id": 3, "Asset Importance": "High", "compensation_control": "Accepted: low risk.", "residual_severity": "Low"},
        # row_id 4 intentionally missing from findings
    ]
    write_triage_columns(wb["Blackduck"], findings)

    ws = wb["Blackduck"]
    # Row 2 (openpyxl row index)
    assert ws.cell(row=2, column=3).value == "High"
    assert ws.cell(row=2, column=4).value == "Upgrade to 4.17.21."
    assert ws.cell(row=2, column=5).value == "High"
    # Row 3
    assert ws.cell(row=3, column=4).value == "Accepted: low risk."
    # Row 4 — not in findings, should remain None (untouched)
    assert ws.cell(row=4, column=4).value is None


# ── generate_summary ──────────────────────────────────────────────────────────

def test_generate_summary_returns_markdown():
    all_triaged = {
        "Blackduck": [
            {"CVE Name": "CVE-2023-1234", "residual_severity": "High", "compensation_control": "Upgrade."},
        ],
        "Coverity": [
            {"Issue Name": "SQL Injection", "residual_severity": "Critical", "compensation_control": "Fix query."},
        ],
    }
    expected_md = "## Overview\nSome text.\n## Critical and High Findings\nMore text."
    with patch("reviewer.anthropic.Anthropic") as MockClient:
        client = MockClient()
        client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=expected_md)]
        )
        result = generate_summary(client, all_triaged)

    assert result == expected_md
    client.messages.create.assert_called_once()


# ── build_triage_payload ──────────────────────────────────────────────────────

def test_build_triage_payload_strips_description():
    findings = [
        {
            "row_id": 2,
            "Libraries": "lodash",
            "Version": "4.17.20",
            "CVE Name": "CVE-2021-23337",
            "Description": "A" * 3000,  # 3000-char description should be excluded
            "CVSS Score": 7.2,
            "Exploit available": True,
            "Match type": "Direct Dependency",
            "Short Term Recommended": "4.17.21",
            "Severity": "High",
            "Asset Importance": "High",
        }
    ]
    payload = build_triage_payload(findings, "Blackduck")
    assert "Description" not in payload[0]
    assert payload[0]["CVE Name"] == "CVE-2021-23337"
    assert payload[0]["row_id"] == 2


# ── validate_triage_chunk (structural verifier) ───────────────────────────────

def _chunk(row_ids):
    return [{"row_id": rid, "Severity": "High", "Asset Importance": "Low"} for rid in row_ids]


def _output(row_ids, sev="High", ctrl="Upgrade to fixed version."):
    return [{"row_id": rid, "residual_severity": sev, "compensation_control": ctrl} for rid in row_ids]


def test_validate_triage_chunk_clean():
    issues = validate_triage_chunk(_chunk([2, 3, 4]), _output([2, 3, 4]))
    assert issues == []


def test_validate_triage_chunk_missing_row():
    issues = validate_triage_chunk(_chunk([2, 3, 4]), _output([2, 4]))  # row 3 missing
    assert any("row_id 3" in i and "missing" in i for i in issues)


def test_validate_triage_chunk_invalid_severity():
    output = _output([2])
    output[0]["residual_severity"] = "EXTREME"
    issues = validate_triage_chunk(_chunk([2]), output)
    assert any("invalid residual_severity" in i for i in issues)


def test_validate_triage_chunk_empty_control():
    output = _output([2])
    output[0]["compensation_control"] = "ok"  # too short (≤ 10 chars)
    issues = validate_triage_chunk(_chunk([2]), output)
    assert any("empty or too short" in i for i in issues)


def test_validate_triage_chunk_empty_control_none():
    output = _output([2])
    output[0]["compensation_control"] = None
    issues = validate_triage_chunk(_chunk([2]), output)
    assert any("empty or too short" in i for i in issues)


# ── _escalation_flags ─────────────────────────────────────────────────────────

def test_escalation_flags_detects_two_level_jump():
    chunk = [{"row_id": 5, "Severity": "Low", "Asset Importance": "Low"}]
    output = [{"row_id": 5, "residual_severity": "Critical", "compensation_control": "Investigate."}]
    flagged = _escalation_flags(chunk, output)
    assert 5 in flagged


def test_escalation_flags_ignores_one_level_jump():
    chunk = [{"row_id": 6, "Severity": "Medium", "Asset Importance": "Low"}]
    output = [{"row_id": 6, "residual_severity": "High", "compensation_control": "Upgrade package."}]
    flagged = _escalation_flags(chunk, output)
    assert 6 not in flagged


def test_escalation_flags_ignores_downgrade():
    chunk = [{"row_id": 7, "Severity": "Critical", "Asset Importance": "Low"}]
    output = [{"row_id": 7, "residual_severity": "Low", "compensation_control": "Accepted: no exploit."}]
    flagged = _escalation_flags(chunk, output)
    assert 7 not in flagged
