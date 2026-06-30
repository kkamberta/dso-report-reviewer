# DSO Report Reviewer — Harness Charter

## Gate 0 Verdict

| Layer | Verdict | Reason |
|---|---|---|
| Structural QC (row coverage, valid enums, non-empty controls) | **loop-eligible** | Pure Python verifier, independent of Claude, bounded retries (max 1 per chunk) |
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

**The verifier is independent of Claude.** It never calls the API.

---

## What belongs where

| If you want to… | Put it in… |
|---|---|
| Add a new valid severity value | `VALID_SEVERITIES` constant in `reviewer.py` — not here |
| Change chunk retry count | `MAX_RETRIES` constant in `reviewer.py` — not here |
| Add a new sheet type | `SHEET_ID_COL` + `TRIAGE_FIELDS` + system prompt in `reviewer.py` — not here |
| Record a recurring correction to the agent's output | `docs/CORRECTION-LOG.md` — not here |

CLAUDE.md holds principles. Facts, enums, and procedures live in code.

---

## Principles

- Structural validation always runs. It is never optional.
- The semantic quality gate is always human. No LLM grades its own output.
- Retries are bounded. A chunk may be retried at most `MAX_RETRIES` times.
- Partial output is better than no output. A failed chunk writes `VALIDATION_FAILED`, not a crash.
- The summary always reports validation failures so the human gate sees them.
