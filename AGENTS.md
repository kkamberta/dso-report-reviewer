# DSO Report Reviewer — Harness Charter

## Gate 0 Verdict

| Layer | Verdict | Reason |
|---|---|---|
| Structural QC (row coverage, valid enums, non-empty controls) | **loop-eligible** | Pure Python verifier, independent of Codex, bounded retries (max 1 per chunk) |
| Semantic QC (advice quality, downgrade justification) | **harness-only** (human-gated, no exceptions) | No objective pass/fail — requires domain judgment |

**Blast radius:** LOW. Writes to local XLSX + MD files only. No external publish, no irreversible side-effects.

---

## Verifier contract (structural)

`validate_triage_chunk(input_chunk, triage_output)` must pass ALL of:

1. Every `row_id` from `input_chunk` appears in `triage_output` (coverage = 100%)
2. `residual_severity` ∈ `{Critical, High, Medium, Low, Info}` for every row
3. `compensation_control` is non-empty (> 10 characters) for every row
4. If `residual_severity` was escalated 2+ levels above the original `Severity`, flag for human review (not a hard fail)

A chunk that fails criteria 1–3 is retried once with an explicit repair prompt.
After one retry, still-failing rows are written with `VALIDATION_FAILED` as the control and flagged in the summary.

**The verifier is independent of Codex.** It never calls the API.

---

## What belongs where

| If you want to… | Put it in… |
|---|---|
| Add a new valid severity value | `VALID_SEVERITIES` constant in `reviewer.py` — not here |
| Change chunk retry count | `MAX_RETRIES` constant in `reviewer.py` — not here |
| Add a new sheet type | `SHEET_ID_COL` + `TRIAGE_FIELDS` + system prompt in `reviewer.py` — not here |
| Record a recurring correction to the agent's output | `docs/CORRECTION-LOG.md` — not here |
| Change behavior, structure, demo flow, UI, or harness contract | Update the related markdown in the same step, including this `AGENTS.md` when the operating rule or harness boundary changes |
| Change review approval behavior | Persist the decision through the agent/output layer so downloaded XLSX/MD artifacts reflect the reviewer decision; UI-only status changes are not acceptable |
| Change MVP demo behavior, endpoint, UI flow, sample job, expected finding, output format, acceptance criterion, or talk track | Update `docs/MVP-DEMO-RUNBOOK.html` in the same step |

AGENTS.md holds principles. Facts, enums, and procedures live in code.

---

## Principles

- Structural validation always runs. It is never optional.
- The semantic quality gate is always human. No LLM grades its own output.
- Retries are bounded. A chunk may be retried at most `MAX_RETRIES` times.
- Partial output is better than no output. A failed chunk writes `VALIDATION_FAILED`, not a crash.
- The summary always reports validation failures so the human gate sees them.
- Every behavior, structure, UI/demo, or harness-contract change must include the related documentation update in the same step. If the change affects how future agents should work in this repo, update this `AGENTS.md` too.
- Reviewer approval is an output decision, not just a UI state. Any approve/override action must be persisted and visible in downloaded reports.
- `docs/MVP-DEMO-RUNBOOK.html` is the source of truth for the customer-facing MVP demo flow. Any MVP demo change must update that runbook in the same step.
