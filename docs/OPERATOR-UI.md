# DSO Report Reviewer Operator UI

## Purpose

`ui/index.html` is the operator-facing mock console for DSO Report Reviewer. It is intentionally separate from `pitch.html`, which remains a demo/presentation page.

`customer-pitch.html` is a separate customer-facing explanation page for management and sales conversations. It answers what the agent is, why a customer would need it, where it fits in the customer environment, how it works, the MVP demo scenario, and common objections.

The UI shows the workflow expected from the container/webhook version:

1. Submit a CI artifact URL and project metadata.
2. Track review job status.
3. Inspect summary output and export paths.
4. Filter findings by scanner, severity, validation status, and review status.
5. Record mock approve/override decisions for human-gated rows.
6. Show a technical command box when patch/upgrade remediation includes an executable package-manager action.

## Preconditions

- A modern browser.
- No backend is required for the current static mock.
- Future backend integration should expose the planned job endpoints from the webhook service.

## How To Open

Open `ui/index.html` directly in a browser.

Open `customer-pitch.html` directly in a browser for the customer pitch version.

For the live demo, start the demo agent and open:

- `http://127.0.0.1:8088/customer-pitch.html`
- `http://127.0.0.1:8088/ui/index.html`
- `http://127.0.0.1:8088/docs/MVP-DEMO-RUNBOOK.html`

Use `docs/MVP-DEMO-RUNBOOK.html` as the source of truth for the customer-facing MVP demo sequence.

## Demo Agent

Run a local demo HTTP agent:

```bash
./scripts/start-demo.sh
```

Create a demo job:

```bash
curl -s -X POST http://127.0.0.1:8088/webhooks/scan-finished \
  -H 'Content-Type: application/json' \
  -d '{"job_id":"build-92619","project":"ap2065","priority":"high","scanner":"mixed","artifact_url":"https://ci.example/artifacts/report.xlsx"}'
```

Useful demo endpoints:

- `GET /healthz`
- `GET /jobs`
- `GET /jobs/{job_id}`
- `GET /jobs/{job_id}/findings`
- `POST /demo/reset`
- `POST /jobs/{job_id}/reviews`
- `GET /jobs/{job_id}/outputs/summary.md`
- `GET /jobs/{job_id}/outputs/annotated.xlsx`

No dev server is required for the current version.

## Verification

- The dashboard loads with sample `build-92619` data.
- The New review form can create a queued mock job.
- Filters update the findings table without page reload.
- Approve and Override buttons update the selected row state.
- The customer pitch page covers the expected customer questions and links to the operator UI.
- The customer pitch page includes a narrow MVP demo scenario with setup, 10-minute room flow, and v1 boundaries.
- The demo agent can create a completed mock job and write summary/XLSX outputs.
- The operator UI can call the demo agent, run the one-click `build-92619` demo job, refresh job status, load findings, and open output downloads.
- The operator UI can reset `build-92619` to a clean pre-approval state through `POST /demo/reset`.
- Approve/Override actions persist through `POST /jobs/{job_id}/reviews` and rewrite the downloadable XLSX/markdown outputs. Do not rely on browser-only review status for customer demos.
- Patch/upgrade remediation rows carry `remediation_commands` from the demo agent, render those commands in the Remediation / control column, and persist them to the `Technical Commands` XLSX column plus the markdown summary.
- Existing reviewer tests still pass with `pytest`.

## Documentation Discipline

Any behavior, structure, UI/demo, or harness-contract change must update the related markdown in the same step. If the change affects how future agents should operate in this repository, update `AGENTS.md` as part of the same change.

Any MVP demo behavior, endpoint, UI flow, sample job, expected finding, output format, acceptance criterion, or talk track change must update `docs/MVP-DEMO-RUNBOOK.html` in the same step.

## Rollback

Delete `ui/index.html`, `customer-pitch.html`, `demo_agent.py`, and this document to remove the UI/pitch/demo additions. The CLI reviewer and existing `pitch.html` page are not changed by this UI.
