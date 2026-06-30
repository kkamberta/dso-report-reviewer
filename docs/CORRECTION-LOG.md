# Correction Log

Each row = one recurring correction caught during a real run.
Add a row **the instant you re-type a correction** — before it evaporates.

Route each correction to the correct fix layer (never to CLAUDE.md):

| # | Date | What Claude did wrong | Where you caught it | Fix layer | Status |
|---|------|----------------------|---------------------|-----------|--------|
| 1 | 2026-06-30 | Treated AGENTS.md as separate from normal related-doc updates and did not update it when the harness/demo operating contract changed. | User correction after demo-agent/UI implementation. | hook/guard | Fixed in AGENTS.md: all behavior, structure, UI/demo, and harness-contract changes require related docs, including AGENTS.md when future-agent rules change. |
| 2 | 2026-06-30 | Approve/Override changed only browser state, so downloaded XLSX/markdown could still show pending review decisions. | User correction while testing triage/approval flow. | tool-output | Fixed in demo agent and UI: review decisions persist through `/jobs/{job_id}/reviews` and rewrite downloadable outputs. |
| 3 | 2026-06-30 | MVP demo flow existed across UI, pitch, docs, and agent behavior but had no single runbook source of truth. | User request to write demo runbook and require updates on every MVP change. | hook/guard | Fixed in AGENTS.md and docs: `docs/MVP-DEMO-RUNBOOK.html` is now required for every MVP demo behavior, endpoint, UI flow, sample job, output, acceptance, or talk-track change. |
| 4 | 2026-06-30 | MVP runbook was markdown-only and harder to read/interact with during demos. | User request to replace markdown runbook with HTML. | tool-output | Fixed by replacing `docs/MVP-DEMO-RUNBOOK.md` with interactive `docs/MVP-DEMO-RUNBOOK.html` and updating AGENTS/docs/tests references. |

<!-- Fix layers:
  tool-internal   : fact / data / logic that should live in reviewer.py
  tool-schema     : missing default or constraint in a function signature
  tool-output     : wrong shape returned (needs a return-contract fix)
  tool-verify     : missing post-call check (goes into validate_triage_chunk)
  hook/guard      : bad action that should be structurally prevented
-->
