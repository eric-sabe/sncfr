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

## Installation

### Step 0: Install Rust (if you don't already have `cargo`)

`sncfr` is compiled with the standard Rust toolchain (**Rust 1.85+**, 2024 Edition). If `cargo --version` is not found on your machine:

- **macOS / Linux**:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
  ```
- **Windows**: Download and run [`rustup-init.exe`](https://rustup.rs/).
- **Linux Only (OS Keyring dependency)**: Install `pkg-config` and `libdbus` headers before building:
  ```bash
  # Debian / Ubuntu
  sudo apt-get update && sudo apt-get install -y pkg-config libdbus-1-dev
  ```
  *(macOS Keychain and Windows Credential Manager work out of the box with no extra packages.)*

---

### Option A: Install the CLI Directly (Recommended for Users)

If you just want the `sncfr` command on your `PATH` without managing a local Git checkout:

```bash
cargo install --git https://github.com/eric-sabe/sncfr.git
```

> [!IMPORTANT]
> `main` is currently **0.2.0-dev** (brownfield instance support, in progress; see [`docs/specs/brownfield-instance-support.md`](docs/specs/brownfield-instance-support.md)). For the latest stable release, pin the tag:
>
> ```bash
> cargo install --git https://github.com/eric-sabe/sncfr.git --tag v0.1.6
> ```

Cargo will download the source, compile an optimized release binary, and install it to `~/.cargo/bin/sncfr`. Verify it works:

```bash
sncfr --version
sncfr --help
```

To upgrade to the latest commit on another machine later, re-run the same command (add `--force` to rebuild even if the version number hasn't changed):

```bash
cargo install --git https://github.com/eric-sabe/sncfr.git --force
```

> [!TIP]
> If your shell says `command not found: sncfr`, add `~/.cargo/bin` to your shell profile (`export PATH="$HOME/.cargo/bin:$PATH"` in `~/.zshrc` or `~/.bashrc`) and open a new terminal.

---

### Option B: Clone & Build from Source (For Local Development & Testing)

If you want to inspect the code, run the test suite, or modify `sncfr` locally:

```bash
# 1. Clone the repository
git clone https://github.com/eric-sabe/sncfr.git
cd sncfr

# 2a. Compile an optimized binary at ./target/release/sncfr
cargo build --release
./target/release/sncfr --version

# 2b. (Optional) Install your local checkout into ~/.cargo/bin/sncfr
cargo install --path .
```

---

## Testing

### 1. Offline Unit & End-to-End (`wiremock`) Test Suite
The repository includes 48 unit tests and a full-binary `wiremock` E2E test suite ([`tests/e2e_cli.rs`](tests/e2e_cli.rs)) that exercises authentication, `doctor`, `show`, `list`, `stats`, dry-run validation, `--write` mutations, and `SNCFR_READ_ONLY=1` locks without requiring a live ServiceNow instance:

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

## Behavior changes from 0.1.x

Changes in 0.2.0 that existing users and agents will notice are listed here as they land on `main`.

| Situation | 0.1.x | 0.2.0 |
|---|---|---|
| A filter or lookup value contains `^`, a line break, or `javascript:` (e.g. `--group "x^ORname=y"`) | interpolated into the query | exit `2` `INVALID_QUERY_VALUE`, nothing sent (`--query` is still sent as written) |
| Untrusted text in a dry-run preview | printed as-is | control characters and terminal escapes removed; Markdown cells escaped |
| `--priority low` on an OOTB, readable instance | exit `2` (no label "low") | exit `0`, value `4`, source `ootb` (alias confirmed by the instance) |
| A choice value or `--set` field that can't be checked (no readable choices, unknown field, unknown type) | sent as typed | exit `8` `UNVERIFIABLE`, nothing written; `--allow-unverified <field>` sends it as typed |
| Dry-run containing such a field | exit `0` | exit `8` (preview still printed) |
| User or group input with 2+ matches | first row silently picked | exit `2` `AMBIGUOUS_REFERENCE` with candidates |
| `list`/`stats`/`feed` `--state`/`--priority` | sent as typed | resolved per table (e.g. `--priority low` → `5` with a pack); unverifiable values sent as typed with an in-band ⚠ |
| `--group Storage` where only `Storage - L2` exists (pack suffixes) | not found | resolves via suffix, shown as `group:suffix " - L2"` |
| A field the instance silently ignored on write | reported as committed | exit `9` `WRITE_NOT_APPLIED` with `not_applied` |
| `--write` with a pack whose `instances` excludes this instance | n/a | exit `2` `PACK_NOT_FOR_INSTANCE` |

---

## Quick Start

### 1. Authenticate via Corporate SSO & Probe Permissions
```bash
# Launches an isolated --app window in your managed browser, captures session + g_ck token into OS Keychain, and closes automatically
sncfr auth login --instance https://mycompany.service-now.com --profile prod

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
sncfr list --from-url "https://mycompany.service-now.com/now/nav/ui/classic/params/target/incident_list.do%3Fsysparm_query%3Dactive%3Dtrue"

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
  - [ADR-0004: Instance Packs for Brownfield ServiceNow Instances](docs/adr/0004-instance-packs.md)

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([`LICENSE-MIT`](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Copyright (c) 2026 Eric Sabetti.
