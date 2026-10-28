# `sncfr` — Agent & Contributor Guide

`sncfr` ("ServiceNow CLI, For Real") is an agent-friendly, read-only-by-default Rust CLI for non-admin ServiceNow users (both ticket-browsers/monitors and ITIL ticket-handlers) to explore, monitor, and act on ServiceNow tickets they have access to.

---

## First Principles (Non-Negotiable)

1. **Durable & Best Design Over Fast/Cheap Shortcuts**
   - Always choose the architecturally sound, resilient, long-term design over brittle hacks or quick workarounds.
   - Enforce invariants at compile time in Rust wherever possible (e.g., type-level separation between `ReadOnlyClient` and `MutatingClient`).
   - Design for real enterprise constraints: Corporate SSO with device posture checks, TLS inspection proxies, custom `u_*`/`x_*` schemas, and variable non-admin ACL permissions.

2. **Spec-Driven Intent (Living Documentation Mandate)**
   - We manage our intent through specifications, architecture decision records, and plans stored in this repository.
   - **Mandatory Rule**: Every feature addition, behavioral change, CLI flag change, or architectural modification **MUST** update the corresponding documentation in [`docs/SPEC.md`](docs/SPEC.md), [`docs/PLAN.md`](docs/PLAN.md), and (when making or revising significant architectural choices) [`docs/adr/`](docs/adr/) in the same change set.
   - Code and specs must never drift apart. When in doubt, update the spec first, then implement.

---

## Documentation Map

- [`docs/SPEC.md`](docs/SPEC.md) — Authoritative product and technical specification for `sncfr`.
- [`docs/PLAN.md`](docs/PLAN.md) — Phased implementation roadmap, milestones, and current status tracker.
- [`docs/TESTING.md`](docs/TESTING.md) — Step-by-step functional testing & live instance smoke-test guide.
- [`docs/specs/`](docs/specs/) — Release design specs (engsys Tier M/L format): normative requirement IDs, contracts, `NA-*` security invariants, `CT-*` test tables, and phase plans. Current: [`brownfield-instance-support.md`](docs/specs/brownfield-instance-support.md) (0.2.0).
- [`docs/adr/`](docs/adr/) — Architecture Decision Records (ADRs) capturing the rationale behind core design choices:
  - [`docs/adr/0001-cdp-isolated-browser-sso.md`](docs/adr/0001-cdp-isolated-browser-sso.md) — Corporate SSO via CDP-driven isolated managed browser window + OS Keychain.
  - [`docs/adr/0002-read-only-default-validated-dry-run.md`](docs/adr/0002-read-only-default-validated-dry-run.md) — Compile-time Read-Only safety gate & Validated Dry-Run Previews.
  - [`docs/adr/0003-batch-api-ticket-dossier-and-acl-degradation.md`](docs/adr/0003-batch-api-ticket-dossier-and-acl-degradation.md) — Single-roundtrip `/api/now/batch` Ticket Dossier and graceful partial ACL degradation.

---

## Upstream Platform Reference

When researching ServiceNow REST APIs, query operators, table structures, or security/ACL behaviors:
- **Do NOT fetch `servicenow.com/docs`** (it is a client-side JavaScript SPA that returns empty shells to tools).
- Use the official LLM-optimized documentation repository: [`ServiceNow/ServiceNowDocs`](https://github.com/ServiceNow/ServiceNowDocs) (specifically [`llms.txt`](https://raw.githubusercontent.com/ServiceNow/ServiceNowDocs/australia/llms.txt) and `markdown/api-reference/rest-apis/`).
