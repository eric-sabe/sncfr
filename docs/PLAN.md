# `sncfr` Implementation Plan & Roadmap

- **Status**: Milestones 0–5 delivered (0.1.x); Milestones 6–10 planned for 0.2.0
- **Last Updated**: 2026-10-28
- **Governing Spec**: [`docs/SPEC.md`](SPEC.md)
- **GitHub Repository**: [`eric-sabe/sncfr`](https://github.com/eric-sabe/sncfr)
- **GitHub Project Board**: [`sncfr Roadmap` (Project #40)](https://github.com/users/eric-sabe/projects/40)

> [!IMPORTANT]
> Per First Principle #2 in [`AGENTS.md`](../AGENTS.md), this plan, [`docs/SPEC.md`](SPEC.md), and the GitHub Project / Milestone issues must be kept in sync as milestones are completed or refined.

---

## Milestone 0: Specification & Architecture Foundation (Completed)

- [x] Feasibility assessment against [`ServiceNow/ServiceNowDocs`](https://github.com/ServiceNow/ServiceNowDocs).
- [x] Resolve core design decisions (`/grill-me` design review).
- [x] Establish living documentation (`AGENTS.md`, `docs/SPEC.md`, `docs/PLAN.md`, `docs/adr/`).
- [x] Initialize GitHub repository (`eric-sabe/sncfr`), CI workflow, Milestones 1–5, Issues `#1`–`#15`, and Project Board (`#40`).

---

## [Milestone 1: Rust Workspace, Config, & Compile-Time Safety Core](https://github.com/eric-sabe/sncfr/milestone/1) (Completed)

- [x] **[#1 — M1.1: Scaffold Cargo package, CLI grammar skeleton (`clap`), and output/error contracts](https://github.com/eric-sabe/sncfr/issues/1)**
  - Initialize Cargo workspace with `clap`, `reqwest` (`rustls-tls-native-roots`), `tokio`, `serde`, `serde_json`, `serde_yaml`, `toml`, `keyring`, `thiserror`, `comfy-table`, `owo-colors`.
  - Complete CLI subcommand definitions and TTY-aware output/error contracts (`0`–`7` exit codes).
- [x] **[#2 — M1.2: Implement profile configuration (`config.toml`), env overrides, and local cache manager](https://github.com/eric-sabe/sncfr/issues/2)**
  - Load `~/.config/sncfr/config.toml` (profiles, `read_only`, saved views) + `SNCFR_*` env overrides + `~/.cache/sncfr/<instance>/` TTL cache manager.
- [x] **[#3 — M1.3: Implement compile-time `ReadOnlyClient` vs. `MutatingClient` (`WritePermit`) safety boundary](https://github.com/eric-sabe/sncfr/issues/3)**
  - Enforce `ReadOnlyClient` (`GET` / `HEAD` / verified `GET`-only `/api/now/batch`) vs. `MutatingClient` (`WritePermit`), with hard-lock support (`SNCFR_READ_ONLY=1` / `read_only = true`) and zero `DELETE` methods.
- [x] **[#4 — M1.4: Implement ServiceNow encoded query builder and UI URL parser (`--from-url`)](https://github.com/eric-sabe/sncfr/issues/4)**
  - Typed `EncodedQuery` builder, relative duration translator (`4h`, `7d`), and parser for classic & Next Experience ServiceNow browser URLs.

---

## [Milestone 2: Corporate SSO Authentication & Doctor](https://github.com/eric-sabe/sncfr/milestone/2) (Completed)

- [x] **[#5 — M2.1: Implement OS Keychain (`keyring`) session store and `sncfr auth import` / token fallbacks](https://github.com/eric-sabe/sncfr/issues/5)**
  - OS Keychain session bundle storage (`cookies` + `g_ck` token) and headless `sncfr auth import` (DevTools "Copy as cURL" / raw headers) + `api-key`/`basic`/`oauth` support.
- [x] **[#6 — M2.2: Implement CDP-driven isolated managed browser login (`sncfr auth login`) & expiry handler](https://github.com/eric-sabe/sncfr/issues/6)**
  - Discover managed Chromium browser, launch isolated `--app` window with CDP, extract `window.g_ck` and domain cookies upon login, and handle `401` expiry context-awarely (TTY vs. agent).
- [x] **[#7 — M2.3: Implement `sncfr auth status` and `sncfr doctor` capability probe (`@me` and ACL matrix)](https://github.com/eric-sabe/sncfr/issues/7)**
  - Resolve and cache `@me` user/group identity (`identity.json`) and probe read access across core tables and `/api/now/batch`.

---

## [Milestone 3: Ticket Resolution, Dossier (`show`), & Queue Exploration](https://github.com/eric-sabe/sncfr/milestone/3) (Completed)

- [x] **[#8 — M3.1: Implement ticket prefix auto-resolver (`sys_number` cache + built-in ITIL prefixes + `task` fallback)](https://github.com/eric-sabe/sncfr/issues/8)**
  - Resolve `INC`, `RITM`, `SCTASK`, `REQ`, `CHG`, `PRB`, `CS`, custom `sys_number` prefixes, and fallback `task` lookups.
- [x] **[#9 — M3.2: Implement `/api/now/batch` client and `sncfr show <TICKET>` Ticket Dossier with graceful ACL degradation](https://github.com/eric-sabe/sncfr/issues/9)**
  - Single-roundtrip Ticket Dossier assembling core fields, non-empty `u_*`/`x_*` custom fields, Service Catalog variables, chronological `sys_journal_field` entries (with inline fallback on `403`), related hierarchy/approvals, and attachments.
- [x] **[#10 — M3.3: Implement `sncfr list`, `sncfr search`, and `sncfr table` with ergonomic filters and saved views (`@<view>`)](https://github.com/eric-sabe/sncfr/issues/10)**
  - Queue listing, full-text search, saved views, and arbitrary read-only table inspection.
- [x] **[#11 — M3.4: Implement `sncfr stats` (Aggregate API), `sncfr feed` (delta monitor), and `sncfr attachments` (`--download`)](https://github.com/eric-sabe/sncfr/issues/11)**
  - `/api/now/stats` queue aggregations, cross-ticket delta activity stream (`sncfr feed --since`), and attachment listing/downloading.

---

## [Milestone 4: Validated Dry-Run Previews, Mutations (`--write`), & Schema Caching](https://github.com/eric-sabe/sncfr/milestone/4) (Completed)

- [x] **[#12 — M4.1: Implement `sncfr schema` introspection (`sys_dictionary` / `sys_choice`) and local TTL metadata cache](https://github.com/eric-sabe/sncfr/issues/12)**
  - Table dictionary and choice list introspection + local TTL caching (`schemas/<table>.json`).
- [x] **[#13 — M4.2: Implement Validated Dry-Run Preview engine and ticket mutations (`comment`, `note`, `update`, `create`, `attach`)](https://github.com/eric-sabe/sncfr/issues/13)**
  - Live-validated dry-run diff previews by default and `--write` execution for `comment`, `note`, `update`, `create`, and `attach`.
- [x] **[#14 — M4.3: Implement `sncfr approvals` and `sncfr catalog` workflows](https://github.com/eric-sabe/sncfr/issues/14)**
  - Approval inspection/action (`sysapproval_approver`) and Service Catalog browsing/ordering (`/api/sn_sc/servicecatalog`).

---

## [Milestone 5: Agent Skill Generator (`sncfr skill`) & E2E Verification](https://github.com/eric-sabe/sncfr/milestone/5) (Completed)

- [x] **[#15 — M5.1: Implement instance-aware `sncfr skill <print|install>` generator and `wiremock` E2E test suite](https://github.com/eric-sabe/sncfr/issues/15)**
  - Tailored `SKILL.md` generator/installer and comprehensive `wiremock` integration test suite.

---

## Post-Plan Audit & Hardening (Completed)

- [x] **[#16 — CI: Fix job-level `hashFiles()` expression in `.github/workflows/ci.yml`](https://github.com/eric-sabe/sncfr/issues/16)**
- [x] **[#17 — Dry-Run: Reconstruct exact copy-pasteable `--write` `commit_command` from CLI args](https://github.com/eric-sabe/sncfr/issues/17)**
- [x] **[#18 — Output: Add OSC 8 clickable terminal hyperlinks and status color-coding in TTY table/dossier views](https://github.com/eric-sabe/sncfr/issues/18)**
- [x] **[#19 — Auth: Unify interactive `401 AuthExpired` auto-reauth retry across all subcommands](https://github.com/eric-sabe/sncfr/issues/19)**

---

## Release 0.2.0: Brownfield Instance Support (Planned — Milestones 6–10)

- **Design spec (Tier L)**: [`docs/specs/brownfield-instance-support.md`](specs/brownfield-instance-support.md). It holds the normative requirement IDs, the contracts, the `NA-*` security invariants, the `CT-*` test table, and the full phase/issue breakdown.
- **Delivery**: one phase = one PR to `main`, and one issue = one commit. `main` carries `0.2.0-dev` until P10 tags `v0.2.0`.
- **Progress**: H ✅ (0.1.6, tags `v0.1.5`/`v0.1.6`) · P0 in review (#70) · P1 in review

| Milestone | Phases | Requirements |
|---|---|---|
| 0.1.6 (hotfix) | H: approvals target fix | APR-4 |
| M6 Safety & Packs | P0 Docs, ADRs & leakcheck · P1 Pack core · P2 Values & write gate · P2.5 References & read filters | DOC-1…4, HYG-1…3, PACK-1…9, SAFE-1…7, Q-1, BF-TEST-1/2ab/3/4 |
| M7 Capabilities & Performance | P3 Capabilities & HTTP · P4 Query performance | CAP-1…6, SAFE-9, PERF-1…6, BF-TEST-2cd |
| M8 Discovery & Identifiers | P5 Identifiers & open rules · P6 Discovery | ID-1…4, Q-2…5, DISC-1…5, BF-TEST-2f |
| M9 Dossier, Approvals, Catalog | P7 Dossier, approvals & marker · P8 Catalog resilience | DOS-1/2, APR-1…3, SAFE-8, CAT-1…4, BF-TEST-2e |
| M10 Workflows & Skills | P9 cmdb & recipes · P9.5 Triage · P10 Skill & release | WF-1…4, TRI-1…7, SKILL-1…4 |

Order: H → P0 → P1 → P2 → P2.5 → P5 → P9/P9.5 → P10. P3 → P4 → P6 branch off P2, and P7 → P8 off P2.5 + P4. There are 48 items in all; the spec's item table gives each one's priority, owner, risk, dependencies, and test cases.

**Hotfix 0.1.6 ([#20](https://github.com/eric-sabe/sncfr/issues/20)):** `approvals approve|reject <ticket>` acted on the first pending approval on the ticket, whoever the approver was, and otherwise on an approval in any state. As of 0.1.6, APR-4 restricts the target to the caller's own pending approval, direct or via group. Release tags (`v0.1.5` at `51d640e`, `v0.1.6`) are pushed after the hotfix merges.

**Tracking:** 48 issues, [#20](https://github.com/eric-sabe/sncfr/issues/20)–[#67](https://github.com/eric-sabe/sncfr/issues/67), on [Project #40](https://github.com/users/eric-sabe/projects/40). Milestones: [Hotfix 0.1.6](https://github.com/eric-sabe/sncfr/milestone/6) ([#20](https://github.com/eric-sabe/sncfr/issues/20)) · [M6](https://github.com/eric-sabe/sncfr/milestone/7) · [M7](https://github.com/eric-sabe/sncfr/milestone/8) · [M8](https://github.com/eric-sabe/sncfr/milestone/9) · [M9](https://github.com/eric-sabe/sncfr/milestone/10) · [M10](https://github.com/eric-sabe/sncfr/milestone/11). The spec's item table links each item to its issue.
