# Correction Log

Each row = one recurring correction caught during a real run.
Add a row **the instant you re-type a correction** — before it evaporates.

Route each correction to the correct fix layer (never to CLAUDE.md):

| # | Date | What Claude did wrong | Where you caught it | Fix layer | Status |
|---|------|----------------------|---------------------|-----------|--------|
| — | — | — | — | — | — |

<!-- Fix layers:
  tool-internal   : fact / data / logic that should live in reviewer.py
  tool-schema     : missing default or constraint in a function signature
  tool-output     : wrong shape returned (needs a return-contract fix)
  tool-verify     : missing post-call check (goes into validate_triage_chunk)
  hook/guard      : bad action that should be structurally prevented
-->
