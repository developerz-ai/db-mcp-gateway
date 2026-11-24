# developerz-ai/db-mcp-gateway — docs

> Index — owned by this repository's maintainers. Add a line when you add a page.

| Where | What lives there |
|---|---|
| [`website/docs/initial-idea/`](../website/docs/initial-idea/) | Why this repository is shaped the way it is: the product idea, the architecture, the tools. |
| [`website/docs/deployment/`](../website/docs/deployment/) | Operator docs: quickstart, IdP guides, target roles, pooler contract, operations (backup, restore, upgrade, rollback), admin API. `tests/doc_drift.rs` keeps their names in step with the code. |
| [`sec/qa/2026-06-29/`](sec/qa/2026-06-29/00-summary.md) | Security deep-dive of v0.1.0: 22 findings, all closed. File paths are as of commit `9250579`. |
| [`CLAUDE.md`](../CLAUDE.md) | How work is done here: the rules a change follows. |
| [`plans/`](plans/) | Execution plans for this repository's own changes; deployments are planned in their own repositories ([why](plans/README.md)). |

The brain itself is the repo root's [`CLAUDE.md`](../CLAUDE.md); the
commands are the `bin/` scripts in its Commands table (start with `bin/setup`, `bin/run`, `bin/check`).
