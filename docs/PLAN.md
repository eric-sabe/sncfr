# `sncfr` Implementation Plan & Roadmap

- **Status**: Active Roadmap
- **Last Updated**: 2026-10-22
- **Governing Spec**: [`docs/SPEC.md`](SPEC.md)

> [!IMPORTANT]
> Per First Principle #2 in [`AGENTS.md`](../AGENTS.md), this plan and [`docs/SPEC.md`](SPEC.md) must be kept in sync as milestones are completed or refined.

---

## Milestone 0: Specification & Architecture Foundation (Current)

- [x] Feasibility assessment against [`ServiceNow/ServiceNowDocs`](https://github.com/ServiceNow/ServiceNowDocs).
- [x] Resolve core design decisions (`/grill-me` design review).
- [x] Establish living documentation (`AGENTS.md`, `docs/SPEC.md`, `docs/PLAN.md`, `docs/adr/`).

---

## Milestone 1: Rust Workspace, Config, & Compile-Time Safety Core

- [ ] Initialize Cargo package (`sncfr`) with core dependencies:
  - CLI & Ergonomics: `clap` (derive), `owo-colors`, `comfy-table`
  - HTTP & TLS: `reqwest` (`rustls-tls-native-roots`, `cookies`, `json`, `multipart`), `tokio`, `url`
  - Serialization & Config: `serde`, `serde_json`, `serde_yaml`, `toml`, `directories`
  - Security & SSO: `keyring`, `tokio-tungstenite` / CDP client for isolated browser session capture
  - Error Handling & Diagnostics: `thiserror`, `miette` or structured error formatter
- [ ] Implement configuration loader (`~/.config/sncfr/config.toml`), environment variable overrides (`SNCFR_*`), and local cache directory manager (`~/.cache/sncfr/<instance>/`).
- [ ] Implement `ReadOnlyClient` vs. `MutatingClient` (`WritePermit`) type-level safety boundary and structured error/exit-code model.
- [ ] Implement ServiceNow encoded query builder & ServiceNow UI URL parser (`--from-url`).

---

## Milestone 2: Corporate SSO Authentication & `doctor`

- [ ] Implement credential storage in OS Keychain (`keyring`) with session bundle serialization (`cookies` + `g_ck` token + timestamps).
- [ ] Implement `sncfr auth login`:
  - Discover installed managed Chromium browser (Chrome, Edge, Brave, Arc) on macOS/Linux/Windows.
  - Launch isolated `--app=https://<instance>.service-now.com` window with CDP debugging port on `127.0.0.1` and persistent profile directory (`~/.local/share/sncfr/browser-profile/<instance>`).
  - Poll/observe navigation via CDP until authenticated on the target instance and `window.g_ck` is populated; extract cookies via `Network.getCookies`, close window, and persist to OS Keychain.
- [ ] Implement `sncfr auth import` (parse pasted DevTools "Copy as cURL" or raw Cookie/X-UserToken headers) and API-Key / Basic auth fallback.
- [ ] Implement context-aware session expiry handler (auto-reauth in interactive TTY, fail-fast `AUTH_EXPIRED` in non-TTY/agent mode).
- [ ] Implement `sncfr auth status` and `sncfr doctor` capability probe (`@me` user/group resolution, ACL checks across core tables and `/api/now/batch`).

---

## Milestone 3: Ticket Resolution, Dossier (`show`), & Queue Exploration (`list`, `search`, `stats`, `feed`)

- [ ] Implement ticket prefix resolver (`INC`, `RITM`, `SCTASK`, `REQ`, `CHG`, `PRB`, `CS`, cached `sys_number` table, and `task` table fallback).
- [ ] Implement `/api/now/batch` client and `sncfr show <TICKET>` **Ticket Dossier** builder:
  - Core fields + automatic non-empty `u_*` / `x_*` custom field extraction.
  - Service Catalog variable resolution (`sc_item_option_mtom` / `sc_item_option`) for `RITM` and `SCTASK`.
  - Chronological `sys_journal_field` activity stream (`comments` and `work_notes`) with graceful fallback to inline `comments_and_work_notes` on `403 Forbidden`.
  - Related hierarchy (parent/child tasks, `sysapproval_approver` approvals, `task_ci`) and `sys_attachment` metadata.
- [ ] Implement `sncfr list` and `sncfr search` with ergonomic flags (`--mine`, `--group`, `--active`, `--state`, `--priority`, `--updated-since`, `--from-url`, `@<saved-view>`).
- [ ] Implement `sncfr stats` using the Aggregate API (`/api/now/stats/{table}`).
- [ ] Implement `sncfr feed` for delta/activity monitoring across matching tickets (`--since`).
- [ ] Implement `sncfr attachments` (list and `--download`) and `sncfr table` (read-only arbitrary table query).

---

## Milestone 4: Validated Dry-Run Previews, Mutations (`--write`), & Schema Caching

- [ ] Implement `sncfr schema` (`sys_dictionary` and `sys_choice` introspection + local TTL cache).
- [ ] Implement Validated Dry-Run Preview engine (resolves display values to internal values/sys_ids, computes before/after diff, prints exact `--write` command).
- [ ] Implement `sncfr comment` and `sncfr note` (dry-run by default, commits with `--write`).
- [ ] Implement `sncfr update` and `sncfr create` (dry-run by default, commits with `--write`).
- [ ] Implement `sncfr attach` (dry-run preview of file metadata + target ticket by default, uploads via `/api/now/attachment/file` with `--write`).
- [ ] Implement `sncfr approvals` and `sncfr catalog` workflows.

---

## Milestone 5: Agent Skill Generator (`sncfr skill`) & End-to-End Verification

- [ ] Implement `sncfr skill <print|install>` to generate a tailored `SKILL.md` incorporating the user's configured instance, saved views, custom prefixes, and safety model.
- [ ] Comprehensive unit and wiremock-based integration test suite covering:
  - `/api/now/batch` Ticket Dossier assembly and partial `403` ACL fallback
  - Read-only / `--write` gate and `SNCFR_READ_ONLY=1` lock
  - ServiceNow URL query parser and encoded query builder
  - Dry-run diff generation
