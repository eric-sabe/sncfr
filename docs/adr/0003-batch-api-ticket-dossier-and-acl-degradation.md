# ADR-0003: Single-Roundtrip `/api/now/batch` Ticket Dossier & Graceful ACL Degradation

- **Status**: Accepted
- **Date**: 2026-10-22

## Context

In ServiceNow, the data a human or AI agent needs to understand a ticket is scattered across at least five tables:
1. The task subtype table (`incident`, `sc_req_item`, `change_request`, `sc_task`, `problem`, etc.)
2. `sys_journal_field` (chronological customer `comments` and internal `work_notes`)
3. `sc_item_option_mtom` / `sc_item_option` (Service Catalog form variables for `RITM` and `SCTASK`)
4. Related records (`task` parent/children, `sysapproval_approver` approvals, `task_ci` configuration items)
5. `sys_attachment` (attached files)

Meanwhile, raw Table API responses return 100+ columns (mostly empty or internal metadata), and non-admin users have varying ACL permissions (e.g., an `itil` fulfiller can read `sys_journal_field` directly, whereas a basic requester might get `403 Forbidden` on `sys_journal_field` while still having access to inline `comments` on the ticket).

## Decision

1. **Composite Ticket Dossier via `/api/now/batch`**:
   - `sncfr show <TICKET>` bundles the ticket record query (`sysparm_display_value=all`), journal query, catalog variable query, related task/approval queries, and attachment metadata query into a single `/api/now/batch` HTTP request.
2. **Curated Core Fields + Automatic Non-Empty Custom Fields (`u_*`, `x_*`)**:
   - Omit empty and noisy system columns by default, while automatically surfacing any non-empty custom instance fields (`u_*` and `x_*`) so organization-specific context is never hidden.
3. **Graceful Partial ACL & Batch Endpoint Degradation**:
   - Evaluate each sub-response in the `/api/now/batch` payload independently.
   - If `/api/now/batch` itself is restricted or unavailable on the instance, automatically fall back to executing the `GET` sub-requests concurrently via standard Table API `GET` calls and wrap them in the same `ServicedSubResponse` envelope.
   - If a sub-request returns `403 Forbidden` (e.g., `sys_journal_field`), fall back to inline `comments_and_work_notes` / `comments` from the main ticket record and annotate the restricted section rather than failing the entire command.

## Consequences

- Reduces latency from 5–6 sequential HTTP calls to 1–2 round-trips.
- Cuts token consumption by ~90% compared to raw Table API JSON while providing significantly richer ticket context.
- Works seamlessly across both high-privilege fulfiller (`itil`) accounts and restricted self-service accounts.

## Amendment (2026-10-28, release 0.2.0)

See [`docs/specs/brownfield-instance-support.md`](../specs/brownfield-instance-support.md) (§Capability record, §Dossier degradation).

- **Batch is an optimization, not the primary path.** `/api/now/batch` is often disabled or unrouted on enterprise instances, so concurrent Table API `GET`s are the normal path. Batch is used only while the per-instance **capability record** (`capabilities.json`, TTL 7 days) says it is `Available` or `Unknown`.
  - A 400 "URI does not represent any resource" or a 404 records it `Unavailable`, and a 403 records it `Unauthorized`. Later invocations skip it until the TTL expires or `sncfr doctor --refresh` runs.
  - Transient failures (5xx, 429, timeout) fall back for that call only.
- **Every dossier section degrades on its own** on `403`, `404`/invalid table, or **timeout**. The section is annotated, JSON carries `sections.<name>.status` and `degraded[]`, and the command still exits 0. Only a failure to fetch the primary record fails the command.
- **Per-request timeout** is configurable (`--timeout`, `SNCFR_TIMEOUT`, profile `timeout_secs`; 1–300 s, default 30).
