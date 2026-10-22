# `sncfr` — ServiceNow CLI, For Real

An agent-friendly, **read-only-by-default** Rust CLI for non-admin ServiceNow users (both ticket-monitors/explorers and ITIL ticket-handlers) to explore, monitor, and act on ServiceNow tickets they have access to.

---

## Why `sncfr`?

- **Zero Instance Plugins Required**: Unlike the official ServiceNow CLI (`snc`), which requires an administrator to install the *CLI Metadata* Store plugin on the instance, `sncfr` runs directly against standard, built-in ServiceNow REST APIs (`/api/now/table`, `/api/now/batch`, `/api/now/stats`, `/api/now/attachment`).
- **Read-Only by Default, Validated Dry-Run on Mutations**: Exploration commands never mutate state. Mutating commands (`comment`, `note`, `update`, `create`, `attach`, `approve`) run a **Validated Dry-Run Preview** against the live instance by default and require an explicit `--write` flag to commit. Ticket deletion is never supported.
- **Corporate SSO Native**: Authenticates via an isolated `--app` window in your enterprise-managed browser over Chrome DevTools Protocol (CDP), preserving Okta FastPass, Microsoft Entra Conditional Access, and client certificates while storing session tokens in the OS Keychain.
- **Single-Roundtrip Ticket Dossiers**: `sncfr show INC0010042` uses `/api/now/batch` to assemble curated ticket fields, non-empty custom fields (`u_*`, `x_*`), Service Catalog variables (for `RITM`/`SCTASK`), chronological comments & work notes (`sys_journal_field`), related tasks/approvals, and attachments in one request—cutting LLM token usage by ~90%.

---

## Living Documentation & Specifications

We manage our intent through living specs and plans in this repository:

- [`AGENTS.md`](AGENTS.md) — First Principles & contributor rules.
- [`docs/SPEC.md`](docs/SPEC.md) — Authoritative product and technical specification.
- [`docs/PLAN.md`](docs/PLAN.md) — Phased implementation roadmap, GitHub Milestones, and status tracker.
- [`docs/adr/`](docs/adr/) — Architecture Decision Records:
  - [ADR-0001: Corporate SSO via CDP-Driven Isolated Managed Browser Window](docs/adr/0001-cdp-isolated-browser-sso.md)
  - [ADR-0002: Compile-Time Read-Only Default and Validated Dry-Run Previews](docs/adr/0002-read-only-default-validated-dry-run.md)
  - [ADR-0003: Single-Roundtrip `/api/now/batch` Ticket Dossier & Graceful ACL Degradation](docs/adr/0003-batch-api-ticket-dossier-and-acl-degradation.md)
