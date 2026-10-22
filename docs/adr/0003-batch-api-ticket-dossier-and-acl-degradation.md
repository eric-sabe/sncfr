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
3. **Graceful Partial ACL Degradation**:
   - Evaluate each sub-response in the `/api/now/batch` payload independently.
   - If a sub-request returns `403 Forbidden` (e.g., `sys_journal_field`), fall back to inline `comments_and_work_notes` / `comments` from the main ticket record and annotate the restricted section rather than failing the entire command.

## Consequences

- Reduces latency from 5–6 sequential HTTP calls to 1–2 round-trips.
- Cuts token consumption by ~90% compared to raw Table API JSON while providing significantly richer ticket context.
- Works seamlessly across both high-privilege fulfiller (`itil`) accounts and restricted self-service accounts.
