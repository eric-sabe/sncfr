# `sncfr` Technical & Product Specification

- **Status**: Living Specification (v0.1.0-draft)
- **Last Updated**: 2026-10-22
- **Target Persona**: Non-admin ServiceNow users (both ticket-monitors/explorers and ITIL fulfillers/handlers) and AI coding/operations agents acting on their behalf.

---

## 1. Motivation & Problem Statement

ServiceNow's official CLI offerings fail the everyday user and AI agent use case:
1. **`snc` (ServiceNow CLI)** requires an instance administrator to install the *CLI Metadata* plugin from the ServiceNow Store before basic record commands work, and exposes only raw, untyped table CRUD (`--table`, `--sysid`, raw encoded queries, JSON blobs) with zero awareness of ticket numbers (`INC*`, `RITM*`, `CHG*`), comments vs. work notes, catalog variables, or activity histories.
2. **`now-sdk` (`@servicenow/sdk`)** is purely an application scaffolding/deployment tool for platform developers.
3. **Raw ServiceNow REST APIs** return 80–150+ mostly empty columns per ticket with opaque `{ link, value }` reference objects, consuming thousands of LLM context tokens per ticket while omitting the most important context (chronological journal entries in `sys_journal_field`, catalog form variables in `sc_item_option_mtom`, approvals, and attachments).

`sncfr` solves this with a zero-plugin, native Rust CLI that speaks in **human ticket identifiers**, defaults strictly to **read-only**, and assembles rich, token-efficient **Ticket Dossiers** in a single HTTP round-trip.

---

## 2. Core Architectural Principles

1. **Zero Instance Plugin Requirement**: Operates exclusively against base-system ServiceNow REST APIs enabled by default (`/api/now/table`, `/api/now/batch`, `/api/now/stats`, `/api/now/attachment`, `/api/sn_sc/servicecatalog`, `/api/sn_chg_rest`).
2. **Read-Only by Default, Write by Explicit Flag (`--write`)**:
   - All exploration/monitoring commands are strictly read-only.
   - Mutating commands (`comment`, `note`, `update`, `create`, `attach`, `approve`) run as **Validated Dry-Run Previews** by default when invoked without `--write`.
   - Ticket deletion is **never** supported at any layer.
   - Profiles or environment variables (`SNCFR_READ_ONLY=1` / `read_only = true`) can hard-lock `sncfr` so even `--write` is rejected.
3. **Corporate SSO & Enterprise Network Native**:
   - First-class Corporate SSO support via a CDP-controlled isolated `--app` window in the user's managed browser (preserving Okta FastPass, Microsoft Entra Conditional Access, and client certificates).
   - Native OS root certificate trust (`rustls-tls-native-roots`) so corporate TLS inspection proxies (e.g., Zscaler, Netskope) work out of the box.
4. **Dual Human / Agent Ergonomics**:
   - Auto-detects TTY: renders clean, scannable tables and terminal views for interactive humans, and emits token-compact Markdown or pruned JSON when piped or invoked by AI agents.

---

## 3. Authentication & Session Lifecycle

### 3.1 Supported Authentication Methods

1. **Corporate SSO Session (`sso`, Default)**:
   - Authenticates REST API requests using session cookies (`JSESSIONID`, `glide_user_route`, `glide_user_activity`, `glide_session_store`, etc.) plus the `X-UserToken: <g_ck>` CSRF/session token header.
   - **`sncfr auth login`**:
     - Locates the system's managed Chromium-based browser (Chrome, Edge, Brave, Arc) and launches an isolated `--app=https://<instance>.service-now.com` window connected via Chrome DevTools Protocol (CDP) using a dedicated profile directory (`~/.local/share/sncfr/browser-profile/<instance>`).
     - Waits for the user to complete SSO/MFA and for the ServiceNow session (`window.g_ck` or authenticated `/api/now/ui/user/current_user`) to become active.
     - Extracts all domain cookies via CDP `Network.getCookies` and `window.g_ck` via `Runtime.evaluate`, closes the window automatically, and stores the encrypted session bundle in the OS Keychain (`keyring`).
2. **Headless / Manual Session Import (`sncfr auth import`)**:
   - Accepts a "Copy as cURL" command from browser DevTools, raw `Cookie` + `X-UserToken` values via stdin or `--file`, explicit `--cookie` / `--user-token` flags, or environment variables (`SNCFR_COOKIE`, `SNCFR_USER_TOKEN`) for remote/SSH/container environments. If only a session `Cookie` is provided, `sncfr auth import` automatically attempts to fetch `window.g_ck` (`X-UserToken`) from `/now/nav/ui/home` or `/navpage.do`.
   - In headless/container environments without an OS Keychain daemon, setting `SNCFR_CREDENTIALS_FILE=/path/to/creds.json` stores credentials in a `0600`-permissioned file store.
3. **Token / Basic / OAuth Fallback (`api-key`, `basic`, `oauth`)**:
   - Supports `x-sn-apikey` header tokens (`SNCFR_API_KEY`), Basic Auth (`SNCFR_USERNAME` + `SNCFR_PASSWORD`), or OAuth 2.0 Bearer tokens (`SNCFR_BEARER_TOKEN`) when available (e.g., on Personal Developer Instances or service accounts).

### 3.2 Session Expiry & Re-Authentication

- When an API call returns `401 Unauthorized` or an invalid session redirect:
  - **Interactive TTY (`stdin` and `stdout` are TTYs)**: Automatically launches the isolated SSO `--app` window (which often completes hands-free via persisted IdP cookies in the isolated profile) and retries the original command.
  - **Non-Interactive / Agent Mode (`!isatty` or `--no-interactive`)**: Fails fast with exit code `3` (`AUTH_EXPIRED`) and outputs a structured error instructing the caller to run `sncfr auth login`.

### 3.3 Capability Probe (`sncfr auth status` & `sncfr doctor`)

- Verifies active session validity and resolves `@me` (`sys_user` record, roles, and `sys_user_grmember` assignment groups).
- Probes read access across key endpoints (`task`, `incident`, `sc_req_item`, `change_request`, `sys_journal_field`, `sys_number`, `sys_choice`, `/api/now/batch`, `/api/now/stats`) and reports an explicit capability matrix for the user's non-admin role set.

---

## 4. Safety & Mutation Gate Architecture

### 4.1 Type-Level Enforcement

In Rust, the HTTP client is split into two distinct types:
- `ReadOnlyClient`: Exposes only `get()`, `head()`, and `batch_get()` (which validates that every batched sub-request uses `method: "GET"`).
- `MutatingClient`: Can only be constructed by passing a verified `WritePermit` token, which requires:
  1. The CLI command was invoked with `--write` (`-w`).
  2. Neither `SNCFR_READ_ONLY=1` nor profile `read_only = true` is set.

### 4.2 Validated Dry-Run Preview (Default for Mutating Commands)

When a mutating command (`comment`, `note`, `update`, `create`, `attach`, `approve`) is called **without** `--write`:
1. `sncfr` uses `ReadOnlyClient` to fetch the current target record (if updating/commenting/attaching) and relevant `sys_choice` / `sys_dictionary` / user / group references.
2. Validates that all provided display values (e.g., `--state "In Progress"`, `--assign-to @me`, `--group "Cloud Ops"`) resolve cleanly to valid ServiceNow values/sys_ids.
3. Outputs a structured **Dry-Run Preview**:
   - Target ticket number, table, `sys_id`, and URL.
   - Before $\to$ After field diff (showing both human display values and underlying internal values).
   - Exact command with `--write` to commit the change.
4. Exits cleanly without mutating the instance.

---

## 5. Command Taxonomy & Grammar

### 5.0 Global CLI Options

All subcommands accept the following global flags:
- `--profile <name>` (`-p`, env `SNCFR_PROFILE`): Select named connection profile from `config.toml`.
- `--instance <url-or-host>` (env `SNCFR_INSTANCE`): Target ServiceNow instance URL or hostname (overrides profile).
- `--output <auto|md|json|yaml|table>` (`-o`, env `SNCFR_OUTPUT`, default `auto`): Output format mode.
- `--json`: Shorthand for `--output json`.
- `--no-interactive`: Never prompt or auto-launch interactive SSO browser windows.
- `--read-only` (env `SNCFR_READ_ONLY`): Enforce hard read-only lock for the invocation (rejects `--write` with exit code `6`).
- `--verbose` (`-v`): Enable verbose diagnostic logging to `stderr`.

### 5.1 Ticket Prefix Auto-Resolution

Commands that accept a `<TICKET>` identifier accept any ticket number (case-insensitive, e.g., `INC0010042`, `ritm0049210`, `CHG0031002`, `SCTASK0019283`, `PRB0010011`, `REQ0010200`, `CS0010400`, or custom prefixes like `SEC0010099`):
1. Looks up the prefix in the local instance metadata cache (seeded from `sys_number` + standard built-in ITIL prefixes).
2. Queries the resolved specific table (e.g., `incident`, `sc_req_item`, `change_request`) by `number=<TICKET>`.
3. If the prefix is unknown or missing from `sys_number`, queries the base `task` table (`number=<TICKET>`) to discover `sys_class_name` (the concrete child table) and `sys_id`, then fetches the full child-table record.

### 5.2 Top-Level Exploration & Monitoring Commands (Read-Only)

- **`sncfr show <TICKET>... [flags]`** (alias: `view`, `get`)
  - Assembles a complete **Ticket Dossier** via a single `/api/now/batch` request:
    1. **Core & Custom Fields**: Curated core fields (`number`, `state`, `priority`, `urgency`, `impact`, `short_description`, `description`, `opened_by`, `caller_id`/`requested_for`, `assignment_group`, `assigned_to`, `sys_created_on`, `sys_updated_on`, `close_code`, `close_notes`, etc.) **plus all non-empty custom fields (`u_*`, `x_*`)** with `sysparm_display_value=all`.
    2. **Catalog Variables (for `sc_req_item` / `sc_task`)**: Queries `sc_item_option_mtom` $\to$ `sc_item_option` to render the question/answer pairs submitted on the Service Catalog form.
    3. **Chronological Activity Stream (`comments` & `work_notes`)**: Queries `sys_journal_field` (`element_id=<sys_id>^ORDERBYsys_created_on`) to render customer-visible comments and internal work notes in chronological order. If `sys_journal_field` returns `403 Forbidden`, gracefully falls back to parsing inline `comments_and_work_notes` / `comments` display values.
    4. **Related Hierarchy & Approvals**: Parent ticket (`parent`, `request`), child tasks (`task.parent=<sys_id>`), approvals (`sysapproval_approver.sysapproval=<sys_id>`), and impacted CIs (`task_ci`).
    5. **Attachments**: Lists attachment metadata (`sys_attachment.table_sys_id=<sys_id>`: file name, size, content type, uploader, timestamp, and `sys_id`).
- **`sncfr list [@<saved-view>] [flags]`** (alias: `ls`)
  - High-level ergonomic filters:
    - `--table <table|prefix>` (defaults to `task` or the saved view's table)
    - `--mine` (`assigned_to=@me` or `caller_id=@me` / `opened_by=@me` / `requested_for=@me`)
    - `--assigned-to <user|@me|unassigned>`
    - `--opened-by <user|@me>`
    - `--group <group|@my-groups>`
    - `--watch-list <user|@me>`
    - `--active` / `--inactive` / `--state <state,...>`
    - `--priority <1..5,...>`
    - `--updated-since <duration|timestamp>` (e.g., `4h`, `2d`, `2026-10-20`)
    - `--created-since <duration|timestamp>`
    - `--from-url <servicenow-ui-url>` (parses `sysparm_query` and table name directly from a pasted ServiceNow browser URL, including `/now/nav/ui/classic/params/target/...` URLs)
    - `--query <encoded_query>` (raw ServiceNow encoded query escape hatch)
    - `--limit <n>`, `--offset <n>`, `--sort <field>` / `--asc` / `--desc`
- **`sncfr search <TEXT> [flags]`**
  - Searches across tickets using ServiceNow full-text index (`123TEXTQUERY321=<TEXT>`) and/or `short_descriptionLIKE<TEXT>^ORdescriptionLIKE<TEXT>`, combinable with all `list` filter flags.
- **`sncfr feed [@<saved-view>] [flags]`**
  - **Activity Feed / Delta Monitor**: Shows a unified chronological stream of recent updates (new comments, work notes, state transitions, newly opened tickets) across tickets matching a filter or saved view (e.g., `sncfr feed @my-team --since 4h`), without requiring the user or agent to open each ticket individually.
- **`sncfr stats [@<saved-view>] [flags]`**
  - **Queue Aggregations**: Uses the ServiceNow Aggregate API (`/api/now/stats/{table}`) to compute instant counts grouped by `--by <state|priority|assignment_group|assigned_to|sys_class_name|category>`.
- **`sncfr attachments <TICKET>`**
  - Lists attachments on `<TICKET>` or downloads them locally (`--download [file-or-sysid] --out-dir <dir>`). Downloading to local disk is a read operation on ServiceNow.

### 5.3 Top-Level Ticket Mutation Commands (Dry-Run by Default, `--write` to Commit)

- **`sncfr comment <TICKET> <MESSAGE> [--file <path>] [--write]`**
  - Posts a customer-visible comment (`comments` field).
- **`sncfr note <TICKET> <MESSAGE> [--file <path>] [--write]`**
  - Posts an internal fulfiller work note (`work_notes` field).
- **`sncfr update <TICKET> [flags] [--write]`**
  - Ergonomic flags: `--state <val>`, `--priority <val>`, `--urgency <val>`, `--impact <val>`, `--assign-to <user|@me|none>`, `--group <group>`, `--short-description <text>`, `--close-code <val>`, `--close-notes <text>`, `--note <work_note>`, `--comment <comment>`, `--set <field=value>...`.
  - Validates choice values and user/group references before previewing or writing.
- **`sncfr create <table|prefix> [flags] [--write]`**
  - Creates a new ticket (e.g., `sncfr create inc --short-description "..." --description "..." --write`).
- **`sncfr attach <TICKET> <FILE_PATH>... [--write]`**
  - Uploads one or more files to `<TICKET>` via `/api/now/attachment/file`.

### 5.4 Specialized Sub-Namespaces

- **`sncfr auth <login|status|import|logout|profiles>`** — Manage authentication and instance profiles.
- **`sncfr approvals <list|show|approve|reject>`** — Inspect pending approvals (`sysapproval_approver`) for `@me` and approve/reject (requires `--write`).
- **`sncfr catalog <search|show|order>`** — Browse Service Catalog items (`/api/sn_sc/servicecatalog/items`), inspect variables, and submit catalog requests (requires `--write`).
- **`sncfr schema <table|prefix> [--choices [field]] [--sync]`** — Inspect table fields, mandatory status, and valid `sys_choice` options; manage local metadata cache.
- **`sncfr table <table_name> [list-flags]`** — Read-only escape hatch for querying arbitrary non-ticket tables (`sys_user`, `sys_user_group`, `cmdb_ci`, `kb_knowledge`, etc.) that the user has ACL permission to read.
- **`sncfr skill <print|install>`** — Generates or installs an instance-aware `SKILL.md` for AI agents (including the user's configured saved views, discovered custom ticket prefixes, and safety rules).
- **`sncfr doctor`** — Runs connectivity, TLS, authentication, and ACL capability diagnostics.

---

## 6. Output Contracts & Error Handling

### 6.1 Output Modes (`--output` / `-o`)

| Mode | When Default | Behavior |
| :--- | :--- | :--- |
| `auto` | Default when `--output` omitted | If `stdout` is a TTY: renders `table` (for `list`/`stats`) or rich terminal dossier (for `show`/`feed`). If `stdout` is piped (`!isatty`): renders `md` (for `show`/`feed`/dry-run) or `json` (for `list`/`stats`). |
| `md` | Piped `show` / `feed` / dry-run | Token-compact GitHub-Flavored Markdown optimized for LLM context windows, omitting null fields and flattening `{ display_value, value }` pairs cleanly. |
| `json` | Piped `list` / `stats` | Deterministic, pruned JSON (`sysparm_display_value=all` normalized to clean objects) with envelope metadata (`count`, `table`, `query`). |
| `yaml` | Explicit `-o yaml` | YAML representation of the pruned JSON structure. |
| `table` | Interactive TTY `list` / `stats` | Aligned terminal tables with status color-coding and clickable terminal hyperlinks (OSC 8) to the ServiceNow record. |

### 6.2 Structured Error Codes & Exit Statuses

| Exit Code | Error Code | Meaning & Agent Remediation |
| :--- | :--- | :--- |
| `0` | `OK` / `DRY_RUN_OK` | Command succeeded (or dry-run validated cleanly). |
| `2` | `INVALID_ARGS` / `VALIDATION_ERROR` | CLI flag error, invalid choice value, or unresolved user/group reference (includes valid choices in error output). |
| `3` | `AUTH_EXPIRED` / `AUTH_REQUIRED` | Session missing or expired. Remediation: run `sncfr auth login`. |
| `4` | `ACL_FORBIDDEN` | Authenticated user lacks ServiceNow permissions for the target resource. |
| `5` | `NOT_FOUND` | Ticket number or record `sys_id` does not exist (or is hidden by query business rules/ACLs). |
| `6` | `READ_ONLY_LOCKED` | `--write` was attempted while `SNCFR_READ_ONLY=1` or profile `read_only = true` is active. |
| `7` | `NETWORK_OR_INSTANCE_ERROR` | TLS, timeout, rate-limit (`429`), or instance `5xx` error. |

---

## 7. Local Configuration & Metadata Cache

### 7.1 Configuration (`~/.config/sncfr/config.toml` or `SNCFR_CONFIG`)

```toml
default_profile = "prod"

[profiles.prod]
instance = "https://mycompany.service-now.com"
auth_method = "sso"
read_only = false # Set to true to hard-block --write on this profile

[profiles.prod.views]
my-active = { table = "task", query = "assigned_toDYNAMIC90d1921e5f510100a9ad2572f2b477fe^active=true" }
team-triage = { table = "incident", query = "assignment_group.name=Cloud Platform^active=true^priorityIN1,2" }
watched = { table = "task", query = "watch_listLIKEjavascript:gs.getUserID()^active=true" }
```

### 7.2 Local Metadata Cache (`~/.cache/sncfr/<instance>/` or `SNCFR_CACHE_DIR`)

- `identity.json`: Cached `@me` user `sys_id`, `user_name`, display name, and group `sys_id`/name list (TTL: 24h).
- `prefixes.json`: Cached `sys_number` prefix $\to$ table name mapping (TTL: 7d), merged with built-in defaults (`INC` $\to$ `incident`, `CHG` $\to$ `change_request`, `RITM` $\to$ `sc_req_item`, `REQ` $\to$ `sc_request`, `SCTASK` $\to$ `sc_task`, `PRB` $\to$ `problem`, `CS` $\to$ `sn_customerservice_case`, `TASK` $\to$ `task`, `KB` $\to$ `kb_knowledge`).
- `schemas/<table>.json`: Cached field labels, custom field metadata (`u_*`, `x_*`), and `sys_choice` valid values per table (TTL: 24h).
