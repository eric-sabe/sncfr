# `sncfr` Technical & Product Specification

- **Status**: Living Specification (v0.2.0-dev; last release v0.1.6)
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

1. **Zero Instance Plugin Requirement**: Operates exclusively against base-system ServiceNow REST APIs (`/api/now/table`, `/api/now/stats`, `/api/now/attachment`, `/api/sn_sc/servicecatalog`, `/api/sn_chg_rest`). `/api/now/batch` is an **optional optimization**: it is frequently disabled or restricted on enterprise instances, so its availability is detected at runtime and recorded per instance, and every command works without it (ADR-0003 amendment).
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
     - Locates the system's managed Chromium-based browser (preferring the OS default browser among Edge, Chrome, Brave, and Arc, or `--browser <edge|chrome|brave|arc|/path/to/exe>`) and launches an isolated `--app=https://<instance>.service-now.com` window connected via Chrome DevTools Protocol (CDP) using a dedicated profile directory (`~/.local/share/sncfr/browser-profile/<instance>`).
     - Waits for the user to complete SSO/MFA and verifies that a real non-guest user session (`NOW.user.name` / `/api/now/ui/user/current_user` != `guest`) and `window.g_ck` are active.
     - Extracts all domain cookies via CDP `Network.getCookies` and `window.g_ck` via `Runtime.evaluate`, closes the window automatically, and stores the encrypted session bundle in the OS Keychain (`keyring`).
2. **Headless / Manual Session Import (`sncfr auth import`)**:
   - Accepts a "Copy as cURL" command from browser DevTools, raw `Cookie` + `X-UserToken` values via stdin or `--file`, explicit `--cookie` / `--user-token` flags, or environment variables (`SNCFR_COOKIE`, `SNCFR_USER_TOKEN`) for remote/SSH/container environments. If only a session `Cookie` is provided, `sncfr auth import` automatically attempts to fetch `window.g_ck` (`X-UserToken`) from `/now/nav/ui/home` or `/navpage.do`.
   - In headless/container environments without an OS Keychain daemon, setting `SNCFR_CREDENTIALS_FILE=/path/to/creds.json` stores credentials in a `0600`-permissioned file store. An Instance Pack with `[auth] allow_credentials_file = false` makes every command exit `2` before that file is opened (ADR-0001 amendment, §7.3).
3. **Token / Basic / OAuth Fallback (`api-key`, `basic`, `oauth`)**:
   - Supports `x-sn-apikey` header tokens (`SNCFR_API_KEY`), Basic Auth (`SNCFR_USERNAME` + `SNCFR_PASSWORD`), or OAuth 2.0 Bearer tokens (`SNCFR_BEARER_TOKEN`) when available (e.g., on Personal Developer Instances or service accounts).

### 3.2 Session Expiry & Re-Authentication

- **Per-API-family 401s (CAP-4)**: a `401` (or login page) from a non-Table API family (`/api/sn_sc/*`, `/api/sn_chg_rest/*`) triggers one fresh Table API probe (`GET /api/now/table/sys_user?sysparm_limit=1`) sent after that 401. If the probe returns JSON 2xx, the account just isn't authorized for that family: exit `4` `ACL_FORBIDDEN` (`ApiFamilyUnauthorized`), with no re-auth prompt, and `catalog_api = unauthorized` recorded for `sn_sc`. A probe 401, redirect, or HTML login page is a real expiry and handled as below. The probe is never cached, so a session that expires mid-run is never masked.
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
   - For every field, a **Source** (`pack`, `ootb`, `cache`, `sys_choice`, `discovered`, `input`, `input + marker`, or `none`) and a **Status** (`verified`, `verified (in-use set)`, `UNVERIFIABLE (<reason>)`, or `n/a (free text)`). JSON carries the same as `diffs[].source` / `diffs[].status`, plus `diffs[].unverifiable` (`would_send`, `reason`, `candidates`, `suggested`).
   - Exact command with `--write` to commit the change.
4. Exits cleanly without mutating the instance (exit `0`), or exits `8` (`UNVERIFIABLE`) when any value could not be confirmed. Dry-run and `--write` run the same check: every mutation of an invocation is checked before the first request is sent, so `--write` with an unverifiable value sends nothing.
5. **Write path**: mutations are built only from resolved values and sent only through the write gate (`src/write_gate.rs`; ADR-0002 amendment). After each record write, the returned record is compared with what was sent (exit `9` on a mismatch).

**Value resolution (SAFE-1)**: every field is first typed (choice, reference, free text, plain, unknown type, or unknown field). Choice values then go through this chain:
1. an authoritative user-pack choice set (complete: a non-match is exit `2`; a contradiction with readable instance metadata is `pack_conflict`; values from a `draft` pack are `draft_pack`);
2. the instance's complete set (cached or live `sys_choice`), where `confirm_required` aliases (the bundled `ootb` ones) apply only when the instance has the same `(value, label)`;
3. an in-use set discovered via the Aggregate API (DISC-2, DISC-3): when steps 1–2 have no set and the field is choice-typed and listed in the pack's `discovery.choice_fields` (task-inherited), `GET /api/now/stats/<table>?sysparm_group_by=<field>` returns the values in use. Reference and free-text fields are never probed. A match is `verified (in-use set)` with source `discovered`, and an `ootb` alias confirmed by the set is source `ootb`. A non-match is exit `8`, never exit `2`, because values never used are missing: `ootb_unconfirmed` when an `ootb` alias matched but its `(value, label)` is not in the set, else `not_seen`. Both list the in-use values as `candidates`. A `403` from stats is recorded as `stats_group_by = unauthorized`, and later runs skip the request;
4. nothing, which gives `UNVERIFIABLE (no_metadata)`.

Fields whose type or existence cannot be established are `UNVERIFIABLE`, never treated as free text. When `sys_dictionary` is forbidden or returns no rows, fields are inferred from one sample record (`display_value=all`, reference links kept). A sampled field whose `link` is `…/api/now/table/<t>/<id>` is typed as a reference to `<t>` when `<t>` passes the table-name rule, and as a reference of unknown table otherwise (DISC-1). Full rules and the normative outcome table: [`docs/specs/brownfield-instance-support.md`](specs/brownfield-instance-support.md) §Field typing and value resolution.

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
- `--verbose` (`-v`, env `SNCFR_VERBOSE`): Enable verbose timestamped diagnostic logging to `stderr` (covering profile resolution, browser discovery, CDP session probing, Keychain storage, and HTTP request/response status).
- `--log-file <path>` (env `SNCFR_LOG_FILE`): Append structured timestamped debug logs to `<path>`.
- `--timeout <secs>` (env `SNCFR_TIMEOUT`, profile `timeout_secs`): Per-request timeout, 1–300 s (default 30); out of range is exit `2`.
- `--allow-unverified <field,...>`: Send the named `UNVERIFIABLE` fields exactly as typed (§4.2, §6.2). Explicit names only (no `*`/`all`; catalog variables as `var:<name>`), never set by env or profile; only on explicit user instruction.
- `--pack <path>` (env `SNCFR_PACK`): Instance Pack layered over the profile's `pack =` for this invocation (§7.3). Rejected (exit `2`) on a profile with `pack_locked = true`.

### 5.1 Ticket Prefix Auto-Resolution

Commands that accept a `<TICKET>` identifier accept any ticket number, with one optional `-` between prefix and digits (e.g. `ABC-1234567`; the separator is kept in the `number=` query, ID-2) (case-insensitive, e.g., `INC0010042`, `ritm0049210`, `CHG0031002`, `SCTASK0019283`, `PRB0010011`, `REQ0010200`, `CS0010400`, or custom prefixes like `SEC0010099`):
1. Looks up the prefix in the effective prefix map (ID-1): the `ootb` pack's defaults, overridden by `sys_number` (when readable), then by prefixes learned from step 3, then by the user pack's `[prefixes]`. Learned prefixes survive a `sys_number` resync.
2. Queries the resolved specific table (e.g., `incident`, `sc_req_item`, `change_request`) by `number=<TICKET>`.
3. A `403` on the table (or on `task` in step 3) is exit `4` `ACL_FORBIDDEN` naming the table (ID-4); only an empty result everywhere is exit `5`.
4. If the prefix is unknown or missing from `sys_number`, queries the base `task` table (`number=<TICKET>`) to discover `sys_class_name` (the concrete child table) and `sys_id`, then fetches the full child-table record.

### 5.2 Top-Level Exploration & Monitoring Commands (Read-Only)

- **`sncfr show <TICKET>... [flags]`** (alias: `view`, `get`)
  - Assembles a complete **Ticket Dossier** from concurrent Table API `GET`s, using a single `/api/now/batch` request as an optimization when the capability record (§7.2) says batch works on this instance. A batch 400 "URI does not represent any resource" or 404 is remembered as `unavailable`, a 403 as `unauthorized`, and later runs skip it. Each section below degrades on its own (`restricted` 403, `unavailable` 404/invalid table, `timed_out`, or `error`): JSON carries `sections.<name>.status` and `degraded[]`, Markdown shows a `⚠ Partial dossier: …` line, and the command still exits 0. Only failing to fetch the ticket itself fails the command:
    1. **Core & Custom Fields**: Curated core fields (`number`, `state`, `priority`, `urgency`, `impact`, `short_description`, `description`, `opened_by`, `caller_id`/`requested_for`, `assignment_group`, `assigned_to`, `sys_created_on`, `sys_updated_on`, `close_code`, `close_notes`, etc.) **plus all non-empty custom fields (`u_*`, `x_*`)** with `sysparm_display_value=all`. Defaults are table-aware (DOS-2): task-derived tables (per the pack `[hierarchy]`, or, for a table the pack does not list, a record carrying `number` and `opened_at`) get the curated core fields plus the pack's `fields.default.<table>.dossier` (nearest along the hierarchy). Other tables (e.g. `cmdb_ci_server`) get that pack list, else `sys_id`, `name`, `sys_class_name`, `sys_updated_on`, never the task core fields. Without `--fields`/`--all-fields`, empty custom fields are omitted unless the pack lists them.
    2. **Catalog Variables (for `sc_req_item` / `sc_task`)**: Queries `sc_item_option_mtom` $\to$ `sc_item_option` to render the question/answer pairs submitted on the Service Catalog form. Reference (type 8) and List Collector (type 21) answers show the referenced record's display value (DOS-1): ids are grouped per table into `sys_idIN` lookups of at most 100, only 32-hex ids are looked up (NA-13), and the display field is the dictionary's `display = true` field, else the first non-empty of `name`, `number`, `short_description`, `user_name`, `title`. Lookups are remembered for the rest of the invocation. An answer that cannot be resolved is shown raw with `(unresolved reference to <table>)`. JSON gains `raw_value` and `unresolved_reference` on those variables. Markdown and terminal output sanitize every instance-sourced string (NA-9): one-line values have control and format characters removed and line breaks shown as `⏎`. In Markdown, description, close notes, and journal bodies are fenced, so they cannot create headings or lists.
    3. **Chronological Activity Stream (`comments` & `work_notes`)**: Queries `sys_journal_field` (`nameIN<table>,task^element_id=<sys_id>^ORDERBYsys_created_on`; the `name` term keeps the query on its index, PERF-3) to render customer-visible comments and internal work notes in chronological order. If `sys_journal_field` returns `403 Forbidden`, gracefully falls back to parsing inline `comments_and_work_notes` / `comments` display values.
    4. **Related Hierarchy & Approvals**: Parent ticket (`parent`, `request`), child tasks (`task.parent=<sys_id>`), approvals (`sysapproval_approver.sysapproval=<sys_id>`), and impacted CIs (`task_ci`).
    5. **Attachments**: Lists attachment metadata (`sys_attachment.table_sys_id=<sys_id>`: file name, size, content type, uploader, timestamp, and `sys_id`).
- **`sncfr list [@<saved-view>] [flags]`** (alias: `ls`)
  - Default columns (no `--fields` and no saved-view fields): the pack's `fields.default.<table>.list`, nearest along the hierarchy, else the pack's `core.list_columns` for ticket tables (DOS-2).
  - High-level ergonomic filters:
    - `--table <table|prefix>` (defaults to `task` or the saved view's table)
    - `--mine` (`assigned_to=@me` or `caller_id=@me` / `opened_by=@me` / `requested_for=@me`)
    - `--assigned-to <user|@me|unassigned>`
    - `--opened-by <user|@me>`
    - `--group <group|@my-groups>` (alias `--assignment-group`; Q-4, Q-5): with pack `groups.suffixes`, a name expands to itself plus each suffix (`--group Network` → `assignment_group.nameINNetwork,Network - L2,Network - L3`), and Markdown/terminal output shows `group: Network → … (suffix expansion)` as a footer. A name containing a comma cannot go in an `IN` list, so it is sent as an `assignment_group.name=…^OR…` chain. `update`/`create` accept `--assignment-group` and `--assign-to-group` as aliases of `--group`.
    - `--watch-list <user|@me>`
    - `--active` / `--inactive` (always literal `active=true` / `active=false`; a note is printed when the table has a pack open rule) / `--state <state,...>`
    - `--open` / `--closed` (Q-2, Q-3): the Instance Pack's `open_rule.<table>` / `closed_rule.<table>` where defined, else `active=true` / `active=false`. `--closed` exits `2` when the table has only an `open_rule`. On `task` with no `task`-level rule, each child table with a rule gets its own `^NQ` block, and the rest use the fallback. Envelopes list the applied rules (`open_rules[]`, with workaround and `defect_ref`), and Markdown/terminal output shows them as a footer.
    - `--priority <1..5,...>`
    - `--state` / `--priority` values resolve per target table through the same chain as mutations (§4.2, Q-1). A `task`-level query with no `task`-level definition requires every child table with a known set (pack or schema cache) to agree, else exit `2` naming the tables. Values that can't be verified are sent as typed and reported in-band (a ⚠ line above the results; envelope `unverified_filters[]`); this never blocks a read.
    - `--updated-since <duration|timestamp>` (e.g., `4h`, `2d`, `2026-10-20`)
    - `--created-since <duration|timestamp>`
    - `--from-url <servicenow-ui-url>` (parses `sysparm_query` and table name directly from a pasted ServiceNow browser URL, including `/now/nav/ui/classic/params/target/...` URLs)
    - `--query <encoded_query>` (raw ServiceNow encoded query escape hatch)
    - `--limit <n>`, `--offset <n>`, `--sort <field>` / `--asc` / `--desc`
    - `--with-count`: also return `total` (asks the instance to count, which can be slow on huge tables; `stats` is the cheaper count path). Without it, the envelope's `has_more` is inferred from `count == limit` (PERF-2).
- **`sncfr search <TEXT> [flags]`**
  - Searches across tickets using ServiceNow full-text index (`123TEXTQUERY321=<TEXT>`) and/or `short_descriptionLIKE<TEXT>^ORdescriptionLIKE<TEXT>`, combinable with all `list` filter flags.
- **`sncfr feed [@<saved-view>] [flags]`**
  - **Activity Feed / Delta Monitor**: Shows a unified chronological stream of recent updates (new comments, work notes, state transitions, newly opened tickets) across tickets matching a filter or saved view (e.g., `sncfr feed @my-team --since 4h`), without requiring the user or agent to open each ticket individually.
- **`sncfr stats [@<saved-view>] [flags]`**
  - **Queue Aggregations**: Uses the ServiceNow Aggregate API (`/api/now/stats/{table}`) to compute instant counts grouped by `--by <state|priority|assignment_group|assigned_to|sys_class_name|category>`.
- **`sncfr attachments <TICKET>`**
  - Lists attachments on `<TICKET>` or downloads them locally (`--download [file-or-sysid] --out-dir <dir>`). Downloading to local disk is a read operation on ServiceNow.

### 5.3 Top-Level Ticket Mutation Commands (Dry-Run by Default, `--write` to Commit)

- **`sncfr comment <TICKET> <MESSAGE> [--file <path>] [--allow-code-tag] [--write]`**
  - Posts a customer-visible comment (`comments` field).
- **`sncfr note <TICKET> <MESSAGE> [--file <path>] [--allow-code-tag] [--write]`**
  - Posts an internal fulfiller work note (`work_notes` field).
- **Agent write marker (SAFE-8, NA-12)**: when a loaded pack sets `audit.agent_write_marker` and the invocation is non-interactive (`--no-interactive`, `SNCFR_AGENT=1`, a non-TTY **stdin**, or profile `agent_marker = "always"`; piping stdout alone does not count), every `comments` / `work_notes` payload (`comment`, `note`, `update --comment/--note`, approval comments) begins with `"<marker> "`. The preview shows the marked text with Source `input + marker`. No flag removes it. The marker records provenance; it is not authentication. A body containing `[code]` (which ServiceNow renders as raw HTML) is exit `2` unless `--allow-code-tag` is given (comment, note, update), and even then a warning is printed. Approval comments have no such flag, so `[code]` there is always refused.
- **`sncfr update <TICKET> [flags] [--write]`**
  - Ergonomic flags: `--state <val>`, `--priority <val>`, `--urgency <val>`, `--impact <val>`, `--assign-to <user|@me|none>`, `--group <group>`, `--short-description <text>`, `--close-code <val>`, `--close-notes <text>`, `--note <work_note>`, `--comment <comment>`, `--set <field=value>...`, `--allow-code-tag`.
  - Validates choice values and user/group references before previewing or writing.
  - **References never guess (SAFE-7)**: `--group` tries an exact match in `@my-groups`, then an exact `sys_user_group` name, then the pack's `groups.suffixes` (e.g. `Storage` → `Storage - L2`). Users match one `user_name`/`email`/`name`. More than one candidate at any step exits `2` `AMBIGUOUS_REFERENCE`, listing candidates (★ marks your own groups) and any pack `suggest_map` suggestion, which is never applied. The preview's Source shows how each reference resolved (`group:exact`, `group:suffix " - L2"`, `group:my_groups`, `user:@me`, ...).
- **`sncfr create <table|prefix> [flags] [--write]`**
  - Creates a new ticket (e.g., `sncfr create inc --short-description "..." --description "..." --write`).
- **`sncfr attach <TICKET> <FILE_PATH>... [--write]`**
  - Uploads one or more files to `<TICKET>` via `/api/now/attachment/file`.

### 5.4 Specialized Sub-Namespaces

- **`sncfr auth <login|status|import|logout|profiles>`** — Manage authentication and instance profiles.
- **`sncfr approvals <list|show|approve|reject>`** — Inspect pending approvals (`sysapproval_approver`) for `@me` and approve/reject (requires `--write`).
  - `list` (APR-1..3) sends two queries at once: `approver=<me>` and `group.assignment_groupIN<@my-groups sys_ids>` (both with the `--state` filter, default `requested`, and `ORDERBYDESCsys_created_on`). Rows are deduplicated by `sys_id`, newest first, and each carries `linked_by: user | group | both`. Rows also carry `group`, `document_id`, and `source_table`. `--all-users` drops both linkage predicates and sends one query. A 403 on the group query keeps the user rows and adds a `warnings[]` entry. The envelope gains `group_query`. The dossier's approvals sub-request adds `document_id` and `source_table`.
  - `approve`/`reject` act only on an approval in state `requested` whose `approver` is `@me` or whose `group.assignment_group` is one of `@my-groups`. Given a ticket, exactly one such approval must exist: none → exit `5` listing the approvals found, more than one → exit `2` listing candidates (re-run with the approval `sys_id`). A directly given approval `sys_id` must meet the same rule. Another approver's record or a non-pending record is never a write target.
- **`sncfr cmdb lookup <host|ip|fqdn|serial|sys_id>`** (WF-1, read-only) — The input is a guarded query value (NA-13), classified as a 32-hex `cmdb_ci/{id}`, an IPv4/IPv6 address (`cmdb_ci_server?ip_address=`, then `cmdb_ci_ip_address` → `nic.cmdb_ci`), an FQDN (`fqdn=X^ORname=X`), or a name (`name=X^ORnameSTARTSWITHX.`, then `serial_number=X`). One match returns the CI's fields (`fields.default.<ci class>.list`, else identity, support group, and status), `cmdb_rel_ci` parents and children (20 each), and open tasks from `task_ci` filtered by the `task` open rule with each term `task.`-prefixed (else `task.active=true`), 20 at most, sorted client-side. More than one match returns `matches[]` with `ambiguous: true` and exit `0`. Agents should ask the user which one is meant. No match is exit `5`.
- **`sncfr catalog <search|show|order>`** — Browse Service Catalog items (`/api/sn_sc/servicecatalog/items`), inspect variables, and submit catalog requests (requires `--write`).
  - **Fallback (CAT-1)**: `search` and `show` use `sn_sc` while capability `catalog_api` is available or unknown. When it is `unauthorized`/`unavailable`, or a call returns a CAP-4 401, 403, or 404, they read the Table API instead: `sc_cat_item` (search text is a guarded query value), active `item_option_new` rows ordered client-side by `order`, and `question_choice` values. Results are annotated `source: table_api_fallback`. A CAP-4 401 is not an expired session, so there is no re-auth.
  - **Variables (CAT-4)**: every `--var` goes through the SAFE chain, named `var:<name>` in previews, `--allow-unverified`, and `unverifiable_fields`. Metadata comes from the `sn_sc` item's `variables[]`, else `item_option_new` / `question_choice`. Select box, multiple choice, and lookup select values must match a choice value or label (`verified`, source `sys_choice`). The set is complete, so a non-match is exit `2` with the choices listed. Reference and list-collector values resolve like `--assign-to` / `--group` (users, groups) or by exact `name` on the referenced table, and are never guessed. Free text is sent as typed. A name the item does not define is `UNVERIFIABLE (unknown_field)`, and unreadable metadata is `no_metadata` (exit `8`, nothing sent).
  - **RITM polling (CAT-2)**: after a committed `order`, `sc_req_item?request=<req sys_id>` (`sys_id,number,cat_item`) is polled with backoff from the pack's `catalog.poll.initial_backoff_ms` (default 500 ms), doubling, capped at 4 s per wait. The total wait is `--poll-timeout <secs>`, else pack `catalog.poll.max_wait_secs`, else 20 s. The report carries the request (`ticket`, `sys_id`) and `items[]` (`sys_id`, `number`, `cat_item`). A timeout or an unreadable `sc_req_item` adds a `warnings[]` entry and still exits `0`.
  - **`--fill-ritm` (CAT-3)**: off by default, and the pack alone never triggers it. It applies the pack's `catalog.post_order_fill.fields` (templates like `"{var.cost_center}"`, filled from the order's resolved `--var` values; a template naming a variable the order does not set is exit `2`) to the requested item the order creates. The dry-run shows a second diff block targeting `<RITM created by this order>`. Every fill value goes through the SAFE chain for `sc_req_item` and is checked with the order before `order_now` is sent, so an unverifiable fill blocks the whole order (exit `8`). Under `--write` the fill is bound to exactly one RITM with `request = <req>` and `cat_item = <ordered item>`. RITMs of other items are skipped with a warning. If none appeared before the polling cap, or several did, the fill is skipped with a warning that carries the exact `sncfr update <RITM> --set … --write` command.
  - `order` has **no** fallback (NA-16). With `catalog_api` `unauthorized`/`unavailable`, known up front or learned during the call, it exits `4` with `Catalog ordering API is not authorized for this account (catalog_api=<state>). Order in the portal: <instance>/sp?id=sc_cat_item&sys_id=<id>.` and sends nothing.
- **`sncfr schema <table|prefix> [--choices [field]] [--sync]`** — Inspect table fields, mandatory status, and valid `sys_choice` options; manage local metadata cache.
- **`sncfr table <table_name> [list-flags]`** — Read-only escape hatch for querying arbitrary non-ticket tables (`sys_user`, `sys_user_group`, `cmdb_ci`, `kb_knowledge`, etc.) that the user has ACL permission to read.
- **`sncfr skill <print|install>`** — Generates or installs an instance-aware `SKILL.md` for AI agents (including the user's configured saved views, discovered custom ticket prefixes, and safety rules).
- **`sncfr doctor [--refresh]`** — Runs connectivity, TLS, authentication, and ACL capability diagnostics; probes the pack's `core.probe_tables` plus `doctor.extra_probe_tables`; and reports:
  - the merged Instance Pack (name, version, status, hash, active workarounds);
  - whether the pack lists this instance;
  - **pack drift** (user-pack choice entries that readable `sys_choice` contradicts);
  - the **capability record** (§7.2).

  Probes are recorded as observations. Tables in `doctor.absent_tables_ok` that return 400/404 are reported as `not installed`, not as problems. `--refresh` forgets the record first and also probes the catalog API. `sncfr auth status` also reports the pack.
- **`sncfr discover [--out <file>] [--force] [--no-samples]`** (DISC-4, DISC-5) — Probes the instance read-only and writes a **draft** Instance Pack (`status = "draft"`, `instances = ["<host>"]`), mode `0600`. The default path is `<config dir>/packs/<instance-host>.draft.pack.toml`. An existing file is never overwritten without `--force` (exit `2`). Probes:
  1. capabilities, as `doctor --refresh` (rewrites `capabilities.json`);
  2. prefixes from `sys_number` and the 200 most recent `task` rows (`number`, `sys_class_name` only), keeping mappings that differ from the bundled defaults;
  3. in-use choice values via the Aggregate API for each choice-typed `discovery.choice_fields` entry (reference and free-text fields are skipped and listed as `# skipped`; a field whose `sys_choice` set is readable needs no entry);
  4. the custom field inventory: `u_*`/`x_*` names and inferred types from one sample per table, as `# custom field:` comments. Choice-typed fields are added to `discovery.choice_fields`;
  5. group-name suffixes from `sys_user_group` names (`sysparm_fields=name`), kept when at least 3 groups end with one and it passes the suffix rule.

  Each entry carries a `# observed:` comment citing its evidence, and each choice set is marked in-use only. The draft's first line warns that it contains instance metadata. It holds no sys_ids, user names, emails, display names, record values, response text, or full group names. Group names are read in memory and only suffix strings are kept. `--no-samples` reads no record rows: it skips the doctor probes, step 2's `task` sample, and steps 4 and 5, so prefixes come from `sys_number` only. It ends by printing the path and five next steps (review, `pack validate`, `pack show`, set `pack =` in the profile, then set `status = "active"`). `pack validate` locations never point into comment lines.
- **`sncfr pack validate <path>`** — Strictly parses and semantically validates one pack file (§7.3). It reports every problem as `<file>:<line>:<col>: <key>: <message>` and exits `2` (`PACK_INVALID`) on errors; warnings (draft status, complete-choice-set notices) still exit `0`. It runs without authentication, even when the profile's own pack is broken.
- **`sncfr pack show [--toml]`** — Prints the merged pack (`ootb` ⊕ profile pack ⊕ `--pack`): a summary with per-entry origin (`ootb`/`profile`/`override`), safety keys, and hash; `--json`/`-o yaml` for the full structure; `--toml` for a re-loadable single pack file.

---

## 6. Output Contracts & Error Handling

### 6.0 Table API Read Defaults (PERF-1, PERF-4)

Every Table API read (direct and inside batch sub-requests) sends `sysparm_no_count=true` (counting very large tables times out) and `sysparm_exclude_reference_link=true`, unless the caller sets them explicitly. `list --with-count` asks for a total, and field-type inference keeps reference links.

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
| `2` | `INVALID_ARGS` / `VALIDATION_ERROR` / `INVALID_QUERY_VALUE` / `PACK_INVALID` | CLI flag error, invalid choice value, or unresolved user/group reference (includes valid choices in error output). `INVALID_QUERY_VALUE`: a value would add, remove, or reorder encoded-query terms (`^`, line breaks, `javascript:`, or `,` inside an `IN` list); request paths are also restricted to plain table names on the instance origin. `PACK_INVALID`: an Instance Pack failed to parse or validate (§7.3). |
| `3` | `AUTH_EXPIRED` / `AUTH_REQUIRED` | Session missing or expired. Remediation: run `sncfr auth login`. |
| `4` | `ACL_FORBIDDEN` | Authenticated user lacks ServiceNow permissions for the target resource. |
| `5` | `NOT_FOUND` | Ticket number or record `sys_id` does not exist (or is hidden by query business rules/ACLs). |
| `6` | `READ_ONLY_LOCKED` | `--write` was attempted while `SNCFR_READ_ONLY=1` or profile `read_only = true` is active. |
| `7` | `NETWORK_OR_INSTANCE_ERROR` | TLS, timeout, rate-limit (`429`), or instance `5xx` error. **Rate limits (SAFE-9)**: on `429`, `Retry-After` (seconds or HTTP-date) is honored, clamped to 60 s per wait and 120 s per request. Reads retry up to 3 times, a PATCH retries once and only on the instance's own JSON 429, and a POST (`create`, catalog order, attachment) is never retried. The envelope then carries `retry_after_secs`. An optional pack `limits.max_requests_per_minute` rate-limits the process. **`WRITE_OUTCOME_UNKNOWN`** (also exit 7): a write timed out or the connection reset after sending, so it may or may not have landed. Run `sncfr show` before any retry, and never re-run a create or order. |
| `8` | `UNVERIFIABLE` | One or more values could not be confirmed against an active pack or instance metadata (§4.2). **Nothing was written.** The preview still prints to stdout; the error envelope lists `unverifiable_fields[{field, input, would_send, reason, candidates, suggested}]`. Agents: show the user `would_send` and candidates, prefer re-running with a candidate value, and use `--allow-unverified <fields>` only when the user explicitly confirms the literal value. |
| `9` | `WRITE_NOT_APPLIED` | The instance accepted the write but returned some fields with a different value than sent (unknown field, field-level write ACL, business rule). The record **was** partly updated; `not_applied[{field, sent, returned}]`. Do not retry; report to the user. Fields absent from the response are listed as `unconfirmed` and do not change the exit code. |
| `2` | `PACK_NOT_FOR_INSTANCE` | `--write` against an instance the merged Instance Pack does not list in `instances` (reads print a warning). |

---

## 7. Local Configuration & Metadata Cache

### 7.1 Configuration (`~/.config/sncfr/config.toml` or `SNCFR_CONFIG`)

```toml
default_profile = "prod"

[profiles.prod]
instance = "https://mycompany.service-now.com"
auth_method = "sso"
read_only = false # Set to true to hard-block --write on this profile
pack = "packs/mycompany.pack.toml" # Optional Instance Pack (§7.3); relative to this file's directory
pack_locked = false # Set to true to reject --pack / SNCFR_PACK overrides
agent_marker = "auto" # "always" applies the pack's agent write marker even interactively (SAFE-8)

[profiles.prod.views]
my-active = { table = "task", query = "assigned_toDYNAMIC90d1921e5f510100a9ad2572f2b477fe^active=true" }
team-triage = { table = "incident", query = "assignment_group.name=Cloud Platform^active=true^priorityIN1,2" }
watched = { table = "task", query = "watch_listLIKEjavascript:gs.getUserID()^active=true" }
```

### 7.2 Local Metadata Cache (`~/.cache/sncfr/<instance>/` or `SNCFR_CACHE_DIR`)

- `identity.json`: Cached `@me` user `sys_id`, `user_name`, display name, and group `sys_id`/name list (TTL: 24h).
- `prefixes.json`: Cached `sys_number` prefix $\to$ table name mapping (TTL: 7d), merged on read with the prefixes of the merged Instance Pack (the bundled `ootb` pack, `src/pack/ootb.pack.toml`, ships 12 defaults (`INC` $\to$ `incident`, `CHG` $\to$ `change_request`, `RITM` $\to$ `sc_req_item`, `REQ` $\to$ `sc_request`, `SCTASK` $\to$ `sc_task`, `TASK` $\to$ `task`, `PRB` $\to$ `problem`, `PTASK` $\to$ `problem_task`, `CTASK` $\to$ `change_task`, `CS` $\to$ `sn_customerservice_case`, `KB` $\to$ `kb_knowledge`, `HR` $\to$ `sn_hr_core_case`). Prefixes learned from the `task` fallback (§5.1 step 3) are added to the same file.
- `schemas/<table>.json`: Cached field labels, custom field metadata (`u_*`, `x_*`), and `sys_choice` valid values per table (TTL: 24h).
- `discovered/<table>.json`: in-use choice sets from the Aggregate API (`source: discovered`, `complete: false`), values and labels only, no counts (TTL: 24h). A field probed with no rows is kept as an empty set, so a re-run inside the TTL sends no stats request.
- `capabilities.json`: per-instance capability record (CAP-1): `batch_api`, `catalog_api`, `choice_table_filter`, `dictionary_readable`, `number_table_readable`, `stats_group_by`, each `available | unavailable | unauthorized | unknown` with source (`observed`, `probe`, or a pack seed), age, HTTP status, and a closed hint (`invalid_table`, `uri_not_resource`, `acl`, `timeout`, `zero_rows`). It never stores response text. An observation stays authoritative for 7 days, then the pack seed (`true` → available, `false` → unavailable), then `unknown`.
- **On-disk format**: every cache file is a JSON envelope `{ "fetched_at": <RFC 3339>, "ttl_seconds": <n>, "data": <payload> }`, written atomically (temp file + rename). A corrupt or unreadable file is treated as a cache miss.

### 7.3 Instance Packs (ADR-0004)

An Instance Pack is a TOML file of per-instance facts. Full schema and semantics: [`docs/specs/brownfield-instance-support.md`](specs/brownfield-instance-support.md) §Pack schema.

- **Layers**: the bundled `ootb` pack (`src/pack/ootb.pack.toml`, the only pack in the binary and the single source of built-in defaults) ⊕ the profile's `pack =` ⊕ `--pack` / `SNCFR_PACK`. Facts replace by key, a user choice set replaces the `ootb` set whole, and `[remove]` deletes keys after its layer is merged.
- **Safety keys merge as a strictest union**: `allow_credentials_file = false` wins, the first `agent_write_marker` sticks, the lowest `max_requests_per_minute` wins, and `instances` is the intersection. No pack key can clear `read_only`, and user packs cannot set `core.known_free_text`.
- **Strict parsing**: unknown keys at any depth, a wrong type, or an unsupported `schema_version` major fail with `PACK_INVALID` (exit `2`), reported as `<file>:<line>:<col>: <message>`.
- **Load order**: the pack loads before the credential store is chosen on every command.
- **Identity**: the merged pack has a SHA-256 hash (`sha256:<12 hex>` in human output).
