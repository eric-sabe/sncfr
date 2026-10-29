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

## Amendment (2026-10-28, release 0.2.0)

See [`docs/specs/brownfield-instance-support.md`](../specs/brownfield-instance-support.md) (§Write gate, §Field typing and value resolution).

- **UNVERIFIABLE outcome, exit 8.** Validation now has a third outcome besides valid and invalid: a value that cannot be confirmed against an active pack or instance metadata. Examples are `sys_choice` that is unreadable or empty, a field whose type cannot be determined, a field name unknown to the dictionary, sample record, and pack, a `draft` pack, or a pack that contradicts the instance. A dry-run with such a field still prints its preview but exits `8`. `--write` sends **zero** mutating requests unless every such field is named in `--allow-unverified`, which takes explicit names only and no wildcard. This replaces 0.1.x's fail-open behavior, where unconfirmable values were sent raw.
- **Write path at the type level.** `MutatingClient` accepts only an `AuthorizedPayload`, and `MutatingClient::authorize` is its only constructor. The payload is bound to a method and path, and every mutation in an invocation is checked before the first request is sent. Dry-run and `--write` share one check function, so they cannot drift.
- **Post-write check, exit 9.** After a PATCH/POST, the returned record is compared with what was sent. A field that comes back with a different value means the instance silently ignored it (an unknown field, a write ACL, or a business rule). That is reported as `not_applied` with exit `9` `WRITE_NOT_APPLIED`. A field absent from the response is reported as `unconfirmed`, and the exit stays 0.
- **No silent targets.** User, group, and approval references never resolve by picking one of several matches. More than one candidate is exit `2` with the candidates listed.
