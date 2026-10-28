# `sncfr` Functional Testing & Live Smoke-Test Guide

This guide walks through testing `sncfr` end-to-end against both the offline mock test suite and a live Corporate SSO ServiceNow instance.

> [!NOTE]
> Phases 0 through 4 of this guide are **100% read-only**—they never write, update, or create any data in ServiceNow. Phase 4 specifically verifies that mutating commands run as **Validated Dry-Run Previews** by default and that hard read-only locks (`SNCFR_READ_ONLY=1`) block `--write`.

---

## Phase 0: Build, Install, & Offline Verification

### 0.1 Run the automated unit & E2E (`wiremock`) test suite
```bash
cargo test --all-targets --all-features
```
- **Expected**: 43 unit tests + 1 full-binary E2E test (`tests/e2e_cli.rs`) pass.

### 0.2 Install `sncfr` into `~/.cargo/bin` (or build release binary)
```bash
cargo install --path .
sncfr --version
sncfr --help
```

---

## Phase 1: Corporate SSO Authentication & Capability Probe (Read-Only)

Replace `https://mycompany.service-now.com` with your actual ServiceNow URL (or short subdomain `mycompany`).

### 1.1 Interactive Corporate SSO Login (`sncfr auth login`)
```bash
sncfr -v auth login --instance https://mycompany.service-now.com --profile prod
```
*(Tip: Pass `-v` / `--verbose` or `--log-file /tmp/sncfr-debug.log` on any command to inspect real-time browser discovery, CDP session probing, Keychain reads/writes, and HTTP status codes.)*
- **What to observe**:
  1. `sncfr` discovers your managed Chromium browser (Chrome, Edge, Brave, or Arc) and launches an isolated `--app` window with a dedicated profile (`~/.config/sncfr/browser-profile/`).
  2. Complete your corporate SSO login (Okta FastPass, Microsoft Entra Conditional Access, Ping, or SAML + MFA).
  3. Once ServiceNow loads and `window.g_ck` + session cookies (`glide_user_route`, `glide_session_store`, etc.) are populated, `sncfr` extracts them over WebSocket CDP, stores the session bundle in the macOS Keychain, automatically closes the browser window, and saves the `prod` profile in `~/.config/sncfr/config.toml`.

### 1.2 Headless / DevTools Fallback (`sncfr auth import`) *(Optional)*
If you ever want to import a session from an existing browser tab without launching a window:
1. Open Chrome DevTools -> **Network** tab on an active ServiceNow tab.
2. Right-click any request to `/api/now/...` or `.do` -> **Copy** -> **Copy as cURL**.
3. Run:
   ```bash
   pbpaste | sncfr auth import --profile prod
   ```
   *(If the copied request was a `GET` without an `X-UserToken` header, `sncfr` automatically scrapes `/now/nav/ui/home` using the imported cookies to extract `window.g_ck`.)*

### 1.3 Verify `@me` Identity & Group Memberships (`sncfr auth status`)
```bash
sncfr auth status
sncfr auth status -o json
```
- **Expected**: Displays your resolved `@me` identity (`display_name`, `user_name`, 32-char `sys_id`) and your `@my-groups` assignment groups (`sys_user_grmember`), cached under `~/.cache/sncfr/<instance>/identity.json`.

### 1.4 Run the Single-Roundtrip ACL Capability Matrix (`sncfr doctor`)
```bash
sncfr doctor
```
- **Expected**:
  - Confirms TLS connectivity, session validity, `@me` resolution, and `/api/now/batch` support.
  - Displays a table of read ACL probes across `task`, `incident`, `sc_request`, `sc_req_item`, `sc_task`, `change_request`, `problem`, `sys_journal_field`, `sys_attachment`, `sysapproval_approver`, `sys_dictionary`, and `sys_choice`.
  - Any table restricted by non-admin ACLs is marked `403 FORBIDDEN (degraded)` rather than failing the command.

---

## Phase 2: Queue Exploration, Saved Views, & Delta Monitoring (Read-Only)

### 2.1 Personal & Team Queues (`sncfr list`)
```bash
# Tickets assigned to you or opened by you
sncfr list --mine --active

# Tickets assigned to any of your groups, updated in the last 7 days
sncfr list --group @my-groups --active --updated-since 7d

# Filter a specific table by priority and state
sncfr list --table incident --active --priority 1,2

# Select custom columns
sncfr list --mine --fields number,state,priority,short_description,u_environment
```
- **Expected**:
  - In an interactive terminal (TTY): renders an aligned UTF-8 table with color-coded `STATE` and `PRIORITY` cells.
  - When piped (`sncfr list --mine --active | head -n 30`): automatically switches to deterministic, pruned JSON (`display_value` + `value` + `ui_url`).

### 2.2 Browser URL Adoption (`--from-url`)
1. In your web browser, build any filtered list in ServiceNow and copy the URL from the address bar (supports both classic `/nav_to.do?uri=incident_list.do%3Fsysparm_query%3D...` and Next Experience `/now/nav/ui/classic/params/target/...` URLs).
2. Run:
   ```bash
   sncfr list --from-url "<PASTE_SERVICENOW_URL>"
   ```
- **Expected**: `sncfr` extracts the target table and `sysparm_query` from the URL and displays the matching records.

### 2.3 Saved Views (`@<view>`)
Add a saved view to `~/.config/sncfr/config.toml` under `[profiles.prod.views.<name>]`:
```toml
[profiles.prod.views.my-triage]
table = "incident"
query = "active=true^priorityIN1,2,3"
description = "Active P1-P3 incidents"
fields = ["number", "priority", "state", "short_description", "assigned_to", "sys_updated_on"]
```
Then run:
```bash
sncfr list @my-triage --updated-since 24h
```

### 2.4 Fast Queue Aggregations (`sncfr stats`) & Activity Feed (`sncfr feed`)
```bash
# Count active tickets across your groups grouped by state (uses /api/now/stats)
sncfr stats --group @my-groups --active --by state

# Count active incidents grouped by priority
sncfr stats --table incident --active --by priority

# Chronological activity feed of comments & work notes across your tickets in the last 24h
sncfr feed --mine --since 24h
```

### 2.5 Full-Text Search (`sncfr search`) & Raw Table Queries (`sncfr table`)
```bash
# Full-text 123TEXTQUERY321 search
sncfr search "VPN" --active --limit 10

# Query any arbitrary table you have read ACLs for
sncfr table sys_user_group --query "active=true" --fields name,manager --limit 10
```

---

## Phase 3: Single-Roundtrip Ticket Dossier & Schema Introspection (Read-Only)

Pick any ticket number from `sncfr list` (e.g., `INC0010042`, `RITM0049210`, `SCTASK0051209`, `CHG0031002`, or a custom prefix like `HR0099123`).

### 3.1 Inspect Ticket Dossier (`sncfr show`)
```bash
# 1. Interactive TTY Dossier (ANSI colors + OSC 8 clickable links)
sncfr show <TICKET>

# 2. Agent / Piped Markdown Dossier (token-compact GFM)
sncfr show <TICKET> | cat

# 3. Structured JSON Dossier
sncfr show <TICKET> -o json
```
- **What to verify**:
  - Prefix auto-resolution (`INC` -> `incident`, `RITM` -> `sc_req_item`, or custom prefix via `sys_number` / `task` promotion).
  - Curated non-empty core fields + non-empty custom fields (`u_*`, `x_*`).
  - For `RITM` / `SCTASK`: Service Catalog variables (`sc_item_option_mtom`) rendered as Question -> Answer pairs.
  - Chronological `comments` and `work_notes` activity stream (or automatic inline fallback if `sys_journal_field` is `403`).
  - Related child tasks, parent links, approvals, impacted CIs, and attachment metadata.

### 3.2 Inspect & Download Attachments (`sncfr attachments`)
```bash
sncfr attachments <TICKET>
sncfr attachments <TICKET> --download /tmp/sncfr-attachments
```

### 3.3 Introspect Table Schema & Valid Choices (`sncfr schema`)
```bash
# List all fields on incident (including inherited task fields)
sncfr schema incident

# List only custom u_* / x_* fields
sncfr schema incident --custom-only

# Inspect valid choice labels and raw values for a field (e.g. state or priority)
sncfr schema incident --choices state
```

---

## Phase 4: Read-Only Safety Gate & Validated Dry-Run Previews (Zero Writes)

Every mutating command in `sncfr` runs as a **Validated Dry-Run Preview** by default when `--write` is omitted.

### 4.1 Dry-Run Comment & Work Note Preview
```bash
sncfr comment <TICKET> "Dry-run test: this comment will NOT be posted"
sncfr note <TICKET> "Dry-run test: this work note will NOT be posted"
```
- **Expected**:
  - Resolves `<TICKET>` against the live instance to confirm it exists and you have read access.
  - Prints `[DRY-RUN PREVIEW — Read-Only Validation Passed; No Changes Written]` with a `BEFORE -> AFTER` table and the exact copy-pasteable `--write` command.
  - **Zero** `PATCH`/`POST` mutations are sent to ServiceNow.

### 4.2 Dry-Run Update with Live Choice & Reference Validation
```bash
# Valid choice label ("In Progress") and @me user reference
sncfr update <TICKET> --state "In Progress" --assign-to @me --note "Triaging ticket"

# Invalid choice label (should fail fast with exit code 2 and list valid choices)
sncfr update <TICKET> --state "DefinitelyNotAValidState"
echo "Exit code: $?"
```
- **Expected**:
  - The first command resolves `"In Progress"` to its raw value (e.g. `2`), resolves `@me` to your user `sys_id`, fetches the current field values on `<TICKET>`, and renders the `BEFORE -> AFTER` diff preview.
  - The second command exits with code `2` (`VALIDATION_ERROR`) and prints the valid `state` choices for that table.

### 4.3 Hard Read-Only Lock (`SNCFR_READ_ONLY=1` / `read_only = true`)
```bash
# Attempt to force a write while SNCFR_READ_ONLY=1 is set
SNCFR_READ_ONLY=1 sncfr comment <TICKET> "Should be blocked" --write
echo "Exit code: $?"

# Verify that dry-run previews still work under SNCFR_READ_ONLY=1
SNCFR_READ_ONLY=1 sncfr comment <TICKET> "Dry-run preview still allowed"
```
- **Expected**:
  - With `--write`, `sncfr` immediately aborts with `error [READ_ONLY_LOCKED]` and exit code `6` before any `WritePermit` or `MutatingClient` can be constructed.
  - Without `--write`, the read-only dry-run preview still succeeds.

---

## Phase 5: Opt-In Live Mutations (`--write`), Workflows, & Agent Skill

> [!CAUTION]
> Commands in **5.1** pass `--write` and will commit real changes to the target ticket in ServiceNow. Only run `--write` against a designated test/sandbox ticket or a ticket you intend to update.

### 5.1 Commit a Live Work Note or Update (`--write`)
```bash
# Post an internal work note
sncfr note <TEST_TICKET> "Testing sncfr --write work note" --write

# Update fields on a test ticket
sncfr update <TEST_TICKET> --assign-to @me --write

# Upload an attachment to a test ticket
echo "diagnostic log sample" > /tmp/sncfr-diag.log
sncfr attach <TEST_TICKET> /tmp/sncfr-diag.log --write
```

### 5.2 Approvals & Service Catalog (`sncfr approvals` & `sncfr catalog`)
```bash
# List pending approvals assigned to @me
sncfr approvals list

# Search Service Catalog items
sncfr catalog search "laptop"

# Inspect variables (mandatory/optional/choices) for a catalog item
sncfr catalog show <ITEM_SYS_ID_OR_NAME>

# Dry-run a catalog order (omit --write to preview without ordering)
sncfr catalog order <ITEM_SYS_ID> --var requested_region=us-east-1
```

### 5.3 Generate & Install the Instance-Aware Agent Skill (`sncfr skill`)
```bash
# Print the generated SKILL.md to stdout
sncfr skill print

# Install SKILL.md into your workspace for coding agents (Claude Code, Antigravity, Cursor)
sncfr skill install .agents/skills/sncfr/SKILL.md
```
