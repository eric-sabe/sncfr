# `sncfr` — ServiceNow CLI, For Real

[![CI](https://github.com/eric-sabe/sncfr/actions/workflows/ci.yml/badge.svg)](https://github.com/eric-sabe/sncfr/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](Cargo.toml)

An agent-friendly, **read-only-by-default** Rust CLI for non-admin ServiceNow users (both ticket-monitors/explorers and ITIL fulfillers/handlers) to explore, monitor, and act on ServiceNow tickets they have access to.

---

## Why `sncfr`?

- **Zero Instance Plugins Required**: Unlike the official ServiceNow CLI (`snc`), which requires an administrator to install the *CLI Metadata* Store plugin on the instance, `sncfr` runs directly against standard, built-in ServiceNow REST APIs (`/api/now/table`, `/api/now/batch`, `/api/now/stats`, `/api/now/attachment`).
- **Read-Only by Default, Validated Dry-Run on Mutations**: Exploration commands never mutate state. Mutating commands (`comment`, `note`, `update`, `create`, `attach`, `approve`) run a **Validated Dry-Run Preview** against the live instance by default and require an explicit `--write` flag to commit. Ticket deletion is never supported (`MutatingClient` has zero `DELETE` methods).
- **Corporate SSO Native**: Authenticates via an isolated `--app` window in your enterprise-managed browser (Chrome, Edge, Brave, Arc) over Chrome DevTools Protocol (CDP), preserving Okta FastPass, Microsoft Entra Conditional Access, and client certificates while storing session tokens in the OS Keychain.
- **Single-Roundtrip Ticket Dossiers**: `sncfr show INC0010042` uses `/api/now/batch` to assemble curated ticket fields, non-empty custom fields (`u_*`, `x_*`), Service Catalog variables (for `RITM`/`SCTASK`), chronological comments & work notes (`sys_journal_field` with automatic `403` inline fallback), related tasks/approvals, and attachments in one request—cutting LLM token usage by ~90%.
- **Dual-Mode Output (Human TTY vs. Coding Agent)**: Automatically renders ANSI-styled dossiers, status color-coding, and OSC 8 clickable ServiceNow links on an interactive terminal, and switches to token-compact GitHub-Flavored Markdown or pruned JSON when piped to an AI agent or script.

---

## Installation & Building from Source

### Prerequisites
- **Rust**: 1.85+ (Rust 2024 Edition)
- **OS Keychain Dependencies**:
  - **macOS**: Native Keychain works out of the box.
  - **Windows**: Native Credential Manager works out of the box.
  - **Linux**: Requires `pkg-config` and `libdbus-1-dev` (Debian/Ubuntu: `sudo apt-get install pkg-config libdbus-1-dev`).

### Compile & Install

```bash
# Install directly from GitHub into ~/.cargo/bin
cargo install --git https://github.com/eric-sabe/sncfr.git

# Or clone and build locally
git clone https://github.com/eric-sabe/sncfr.git
cd sncfr

# Build optimized release binary (./target/release/sncfr)
cargo build --release

# Or install the local checkout into ~/.cargo/bin
cargo install --path .
```

---

## Testing

### 1. Offline Unit & End-to-End (`wiremock`) Test Suite
The repository includes 43 unit tests and a full-binary `wiremock` E2E test suite ([`tests/e2e_cli.rs`](tests/e2e_cli.rs)) that exercises authentication, `doctor`, `show`, `list`, `stats`, dry-run validation, `--write` mutations, and `SNCFR_READ_ONLY=1` locks without requiring a live ServiceNow instance:

```bash
# Run all unit and integration tests
cargo test --all-targets --all-features

# Check formatting and Clippy lints (enforced in CI)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

### 2. Live Instance Functional & Smoke Testing
See [`docs/TESTING.md`](docs/TESTING.md) for a step-by-step functional test plan against a live Corporate SSO ServiceNow instance (Phases 0–4 are 100% read-only, including Validated Dry-Run Previews and `SNCFR_READ_ONLY=1` lock verification).

---

## Quick Start

### 1. Authenticate via Corporate SSO & Probe Permissions
```bash
# Launches an isolated --app window in your managed browser, captures session + g_ck token into OS Keychain, and closes automatically
sncfr auth login --instance https://your-instance.service-now.com --profile prod

# Or import a "Copy as cURL" snippet from browser DevTools in headless environments
pbpaste | sncfr auth import --profile prod

# Inspect @me identity, @my-groups memberships, and ACL capability matrix across 12 tables
sncfr auth status
sncfr doctor
```

### 2. Explore Queues, Stats, & Activity Feeds (Read-Only)
```bash
# Active tickets assigned to you or opened by you
sncfr list --mine --active

# Active tickets across all of your assignment groups updated in the last 7 days
sncfr list --group @my-groups --active --updated-since 7d

# Adopt any filtered list URL copied from the ServiceNow browser address bar
sncfr list --from-url "https://your-instance.service-now.com/now/nav/ui/classic/params/target/incident_list.do%3Fsysparm_query%3Dactive%3Dtrue"

# Fast server-side counts grouped by state (/api/now/stats)
sncfr stats --group @my-groups --active --by state

# Chronological activity feed of comments & work notes across your tickets in the last 4 hours
sncfr feed --mine --since 4h
```

### 3. Inspect a Single-Roundtrip Ticket Dossier (`sncfr show`)
```bash
# Auto-resolves INC, RITM, SCTASK, REQ, CHG, PRB, CS, or custom sys_number prefixes
sncfr show INC0010042
sncfr show RITM0049210

# Introspect table schema and valid choice values
sncfr schema incident --choices state
```

### 4. Validated Dry-Run Previews vs. `--write` Mutations
Every mutating command runs a **live read-only validation and `BEFORE -> AFTER` diff preview** by default. Nothing is written unless `--write` is passed:
```bash
# 1. Validated Dry-Run Preview (resolves ticket, choice labels, and @me WITHOUT writing to ServiceNow)
sncfr update INC0010042 --state "In Progress" --assign-to @me --note "Investigating gateway logs"

# 2. Commit the mutation by adding --write
sncfr update INC0010042 --state "In Progress" --assign-to @me --note "Investigating gateway logs" --write

# 3. Hard Read-Only Lock for monitoring agents (blocks --write with exit code 6)
export SNCFR_READ_ONLY=1
```

### 5. Install the Instance-Aware Agent Skill (`SKILL.md`)
```bash
sncfr skill install .agents/skills/sncfr/SKILL.md
```

---

## Living Documentation & Architecture

We manage our intent through living specifications, plans, and architecture decision records in this repository:

- [`AGENTS.md`](AGENTS.md) — First Principles & contributor guide.
- [`docs/SPEC.md`](docs/SPEC.md) — Authoritative product and technical specification.
- [`docs/PLAN.md`](docs/PLAN.md) — Phased implementation roadmap, GitHub Milestones, and status tracker.
- [`docs/TESTING.md`](docs/TESTING.md) — Step-by-step functional testing and live Corporate SSO smoke-test guide.
- [`docs/adr/`](docs/adr/) — Architecture Decision Records:
  - [ADR-0001: Corporate SSO via CDP-Driven Isolated Managed Browser Window](docs/adr/0001-cdp-isolated-browser-sso.md)
  - [ADR-0002: Compile-Time Read-Only Default and Validated Dry-Run Previews](docs/adr/0002-read-only-default-validated-dry-run.md)
  - [ADR-0003: Single-Roundtrip `/api/now/batch` Ticket Dossier & Graceful ACL Degradation](docs/adr/0003-batch-api-ticket-dossier-and-acl-degradation.md)

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Copyright (c) 2026 Eric Sabetti.
