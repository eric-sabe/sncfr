# ADR-0002: Compile-Time Read-Only Default and Validated Dry-Run Previews

- **Status**: Accepted
- **Date**: 2026-10-22

## Context

`sncfr` is designed for both human users and autonomous AI agents exploring and handling production ServiceNow tickets. An agent exploring a queue must never accidentally modify a ticket, post a public customer comment instead of an internal work note, or change ticket state unless explicitly instructed and authorized.

## Decision

1. **Read-Only by Default at the Type Level**:
   - Separate the HTTP client into `ReadOnlyClient` (capable only of `GET`, `HEAD`, and verified `GET`-only `/api/now/batch` calls) and `MutatingClient`.
   - `MutatingClient` requires a `WritePermit` token that can only be constructed when `--write` (`-w`) is explicitly passed on the CLI **and** neither `SNCFR_READ_ONLY=1` nor profile `read_only = true` is active.
2. **Validated Dry-Run Preview by Default**:
   - Invoking any mutating command (`comment`, `note`, `update`, `create`, `attach`, `approve`) without `--write` executes a **Validated Dry-Run Preview** using `ReadOnlyClient`:
     - Fetches the target record and validates all field names, `sys_choice` labels, and user/group references against the live instance.
     - Renders a clear Before $\to$ After diff and prints the exact `--write` command to commit the change.
3. **No Record Deletion**:
   - `sncfr` never exposes `DELETE` operations on ticket records.

## Consequences

- AI agents can safely test and preview mutations (verifying field mappings and choice values against the live instance) before asking the user or passing `--write`.
- Users who only want to monitor/browse tickets can set `read_only = true` in their profile (or `SNCFR_READ_ONLY=1`) for a hard guarantee that no write request can ever leave the process.
