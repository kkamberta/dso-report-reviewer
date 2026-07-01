from pathlib import Path
import tomllib


ROOT = Path(__file__).parent.parent
UI = ROOT / "ui" / "index.html"
DOC = ROOT / "docs" / "OPERATOR-UI.md"
RUNBOOK = ROOT / "docs" / "MVP-DEMO-RUNBOOK.html"
CUSTOMER_PITCH = ROOT / "customer-pitch.html"
PYPROJECT = ROOT / "pyproject.toml"
START_DEMO = ROOT / "scripts" / "start-demo.sh"
SMOKE_DEMO = ROOT / "scripts" / "smoke-demo.py"


def test_project_metadata_supports_plain_uv_test_command():
    metadata = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))

    dependencies = "\n".join(metadata["project"]["dependencies"])
    dev_dependencies = "\n".join(metadata["dependency-groups"]["dev"])
    assert "anthropic" in dependencies
    assert "openpyxl" in dependencies
    assert "pytest" in dev_dependencies

    script = START_DEMO.read_text(encoding="utf-8")
    assert "uv run python demo_agent.py" in script
    assert "--with openpyxl" not in script

    smoke = SMOKE_DEMO.read_text(encoding="utf-8")
    assert "run_smoke" in smoke
    assert "/jobs/build-92619/reviews" in smoke
    assert "Technical Commands" in smoke


def test_operator_ui_exists_and_is_static_html():
    html = UI.read_text(encoding="utf-8")

    assert "<title>DSO Report Reviewer - Operator UI</title>" in html
    assert 'id="reviewForm"' in html
    assert 'id="jobList"' in html
    assert 'id="findingsBody"' in html
    assert "const initialJobs" in html


def test_operator_ui_has_required_workflow_controls():
    html = UI.read_text(encoding="utf-8")

    required_controls = [
        'id="artifactUrl"',
        'id="projectCode"',
        'id="priority"',
        'id="scanner"',
        'id="severityFilter"',
        'id="scannerFilter"',
        'id="flagFilter"',
        'id="reviewFilter"',
        'id="runDemoButton"',
        'id="resetDemoButton"',
        'id="refreshJobsButton"',
        'data-approve-row',
        'data-override-row',
        "remediationCommands",
        "command-box",
        "mvn versions:use-dep-version",
        "API_BASE",
        "/webhooks/scan-finished",
        "/demo/reset",
        "/reviews",
        "MVP-DEMO-RUNBOOK.html",
    ]

    for control in required_controls:
        assert control in html


def test_operator_ui_documents_how_to_open_and_rollback():
    doc = DOC.read_text(encoding="utf-8")

    assert "Open `ui/index.html` directly in a browser." in doc
    assert "Open `customer-pitch.html` directly in a browser" in doc
    assert "docs/MVP-DEMO-RUNBOOK.html" in doc
    assert "No dev server is required" in doc
    assert "uv run pytest" in doc
    assert "uv run python scripts/smoke-demo.py" in doc
    assert "Rollback" in doc


def test_mvp_demo_runbook_covers_live_demo_flow():
    runbook = RUNBOOK.read_text(encoding="utf-8")

    required_text = [
        "DSO Report Reviewer MVP Demo Runbook",
        "Preconditions",
        "uv run pytest",
        "uv run python scripts/smoke-demo.py",
        "Run demo job",
        "Reset demo",
        "build-92619",
        "POST http://127.0.0.1:8088/jobs/build-92619/reviews",
        "Approved Review Decisions",
        "Patch/upgrade remediations show a technical command box.",
        "Acceptance Criteria",
        "Troubleshooting",
        "Rollback",
        "Any MVP demo behavior",
    ]

    for text in required_text:
        assert text in runbook


def test_customer_pitch_answers_core_customer_questions():
    html = CUSTOMER_PITCH.read_text(encoding="utf-8")

    required_text = [
        "What is it?",
        "Why should a customer have it?",
        "Where can it be used?",
        "How it works",
        "MVP demo scenario",
        "10-minute room demo",
        "MVP includes",
        "MVP does not include",
        "Common customer questions",
        "Is this replacing our security scanners?",
        "Can it decide risk automatically?",
        "Where does it run?",
        "Deployment picture: after scan, before approval",
        "retry loop:",
        "missing row, bad enum, empty control",
        "valid output",
        "Before: scanner XLSX export",
        "After: reviewer XLSX + summary",
        "Open operator UI",
    ]

    for text in required_text:
        assert text in html
