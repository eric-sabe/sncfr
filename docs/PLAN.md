# `sncfr` Implementation Plan & Roadmap

- **Status**: Active Roadmap
- **Last Updated**: 2026-10-22
- **Governing Spec**: [`docs/SPEC.md`](SPEC.md)
- **GitHub Repository**: [`eric-sabe/sncfr`](https://github.com/eric-sabe/sncfr) (Private)
- **GitHub Project Board**: [`sncfr Roadmap` (Project #40)](https://github.com/users/eric-sabe/projects/40)

> [!IMPORTANT]
> Per First Principle #2 in [`AGENTS.md`](../AGENTS.md), this plan, [`docs/SPEC.md`](SPEC.md), and the GitHub Project / Milestone issues must be kept in sync as milestones are completed or refined.

---

## Milestone 0: Specification & Architecture Foundation (Completed)

- [x] Feasibility assessment against [`ServiceNow/ServiceNowDocs`](https://github.com/ServiceNow/ServiceNowDocs).
- [x] Resolve core design decisions (`/grill-me` design review).
- [x] Establish living documentation (`AGENTS.md`, `docs/SPEC.md`, `docs/PLAN.md`, `docs/adr/`).
- [x] Initialize private GitHub repository (`eric-sabe/sncfr`), CI workflow, Milestones 1–5, Issues `#1`–`#15`, and Project Board (`#40`).

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

## [Milestone 3: Ticket Resolution, Dossier (`show`), & Queue Exploration](https://github.com/eric-sabe/sncfr/milestone/3)

- [x] **[#8 — M3.1: Implement ticket prefix auto-resolver (`sys_number` cache + built-in ITIL prefixes + `task` fallback)](https://github.com/eric-sabe/sncfr/issues/8)**
  - Resolve `INC`, `RITM`, `SCTASK`, `REQ`, `CHG`, `PRB`, `CS`, custom `sys_number` prefixes, and fallback `task` lookups.
- [x] **[#9 — M3.2: Implement `/api/now/batch` client and `sncfr show <TICKET>` Ticket Dossier with graceful ACL degradation](https://github.com/eric-sabe/sncfr/issues/9)**
  - Single-roundtrip Ticket Dossier assembling core fields, non-empty `u_*`/`x_*` custom fields, Service Catalog variables, chronological `sys_journal_field` entries (with inline fallback on `403`), related hierarchy/approvals, and attachments.
- [ ] **[#10 — M3.3: Implement `sncfr list`, `sncfr search`, and `sncfr table` with ergonomic filters and saved views (`@<view>`)](https://github.com/eric-sabe/sncfr/issues/10)**
  - Queue listing, full-text search, saved views, and arbitrary read-only table inspection.
- [ ] **[#11 — M3.4: Implement `sncfr stats` (Aggregate API), `sncfr feed` (delta monitor), and `sncfr attachments` (`--download`)](https://github.com/eric-sabe/sncfr/issues/11)**
  - `/api/now/stats` queue aggregations, cross-ticket delta activity stream (`sncfr feed --since`), and attachment listing/downloading.

---

## [Milestone 4: Validated Dry-Run Previews, Mutations (`--write`), & Schema Caching](https://github.com/eric-sabe/sncfr/milestone/4)

- [ ] **[#12 — M4.1: Implement `sncfr schema` introspection (`sys_dictionary` / `sys_choice`) and local TTL metadata cache](https://github.com/eric-sabe/sncfr/issues/12)**
  - Table dictionary and choice list introspection + local TTL caching (`schemas/<table>.json`).
- [ ] **[#13 — M4.2: Implement Validated Dry-Run Preview engine and ticket mutations (`comment`, `note`, `update`, `create`, `attach`)](https://github.com/eric-sabe/sncfr/issues/13)**
  - Live-validated dry-run diff previews by default and `--write` execution for `comment`, `note`, `update`, `create`, and `attach`.
- [ ] **[#14 — M4.3: Implement `sncfr approvals` and `sncfr catalog` workflows](https://github.com/eric-sabe/sncfr/issues/14)**
  - Approval inspection/action (`sysapproval_approver`) and Service Catalog browsing/ordering (`/api/sn_sc/servicecatalog`).

---

## [Milestone 5: Agent Skill Generator (`sncfr skill`) & E2E Verification](https://github.com/eric-sabe/sncfr/milestone/5)

- [ ] **[#15 — M5.1: Implement instance-aware `sncfr skill <print|install>` generator and `wiremock` E2E test suite](https://github.com/eric-sabe/sncfr/issues/15)**
  - Tailored `SKILL.md` generator/installer and comprehensive `wiremock` integration test suite.
