use crate::cache::InstanceCache;
use crate::cli::ShowArgs;
use crate::client::{
    BatchGetSubRequest, ReadOnlyClient, extract_field_display, extract_field_pair,
    extract_field_value,
};
use crate::error::SncfrError;
use crate::output::{ResolvedOutputFormat, osc8_link, styled_table_cell};
use crate::resolve::resolve_ticket;
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldValue {
    pub display_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<String>,
}

impl FieldValue {
    pub fn from_pair(display_value: String, raw_value: String) -> Self {
        let raw_opt = if raw_value != display_value && !raw_value.is_empty() {
            Some(raw_value)
        } else {
            None
        };
        Self {
            display_value,
            raw_value: raw_opt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogVariable {
    pub question: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// `"comments"` (customer-visible) or `"work_notes"` (internal fulfiller).
    pub element: String,
    pub author: String,
    pub timestamp: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityStreamSection {
    pub entries: Vec<JournalEntry>,
    #[serde(default)]
    pub degraded_inline_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedTaskSummary {
    pub number: String,
    pub table: String,
    pub sys_id: String,
    pub state: String,
    pub short_description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub sys_id: String,
    pub approver: String,
    pub state: String,
    pub updated_on: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_item: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub child_tasks: Vec<RelatedTaskSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<ApprovalSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impacted_cis: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub sys_id: String,
    pub file_name: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub created_by: String,
    pub created_on: String,
}

/// Complete Ticket Dossier assembled via `/api/now/batch` (`docs/SPEC.md` Section 5.2 & ADR-0003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketDossier {
    pub number: String,
    pub table: String,
    pub sys_id: String,
    pub ui_url: String,
    pub core_fields: BTreeMap<String, FieldValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_fields: BTreeMap<String, FieldValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub catalog_variables: Vec<CatalogVariable>,
    pub activity_stream: ActivityStreamSection,
    pub related: RelatedSection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acl_warnings: Vec<String>,
    /// Status of every fetched section (CAP-3): `ok`, `restricted` (403), `unavailable` (404 or
    /// invalid table), `timed_out`, or `error`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, SectionStatus>,
    /// Sections that are not `ok`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionStatus {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What happened to one sub-request.
fn section_status(sub: &crate::client::ServicedSubResponse) -> SectionStatus {
    let (status, detail) = match sub.status_code {
        200..=299 => ("ok", None),
        403 => ("restricted", Some("403 Forbidden".to_string())),
        404 => (
            "unavailable",
            Some("not available on this instance (404)".to_string()),
        ),
        408 => (
            "timed_out",
            Some(format!(
                "timed out after {}s",
                crate::policy::current().timeout.as_secs()
            )),
        ),
        400 if sub
            .error_message
            .as_deref()
            .is_some_and(|m| m.to_ascii_lowercase().contains("invalid table")) =>
        {
            ("unavailable", Some("invalid table".to_string()))
        }
        code => ("error", Some(format!("HTTP {code}"))),
    };
    SectionStatus {
        status: status.to_string(),
        detail,
    }
}

/// Assembles a [`TicketDossier`] for a single ticket identifier using a composite `/api/now/batch` request.
pub async fn assemble_ticket_dossier(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &ShowArgs,
    ticket_id: &str,
) -> Result<TicketDossier, SncfrError> {
    let resolved = resolve_ticket(client, cache, ticket_id).await?;
    let base_url = client.base_url().as_str().trim_end_matches('/');
    let ui_url = format!(
        "{base_url}/nav_to.do?uri={}.do?sys_id={}",
        resolved.table, resolved.sys_id
    );

    // 1. Extract core & custom (`u_*`, `x_*`) fields from `resolved.record`
    let mut core_fields = BTreeMap::new();
    let mut custom_fields = BTreeMap::new();

    if !args.fields.is_empty() {
        for field_name in &args.fields {
            let trimmed = field_name.trim();
            if let Some((disp, raw)) = extract_field_pair(&resolved.record, trimmed) {
                core_fields.insert(trimmed.to_string(), FieldValue::from_pair(disp, raw));
            }
        }
    } else if args.all_fields {
        if let Some(obj) = resolved.record.as_object() {
            for k in obj.keys() {
                if let Some((disp, raw)) = extract_field_pair(&resolved.record, k) {
                    if k.starts_with("u_") || k.starts_with("x_") {
                        custom_fields.insert(k.clone(), FieldValue::from_pair(disp, raw));
                    } else {
                        core_fields.insert(k.clone(), FieldValue::from_pair(disp, raw));
                    }
                }
            }
        }
    } else {
        for field_name in &crate::pack::active().core.dossier_core_fields {
            if let Some((disp, raw)) = extract_field_pair(&resolved.record, field_name) {
                core_fields.insert(field_name.to_string(), FieldValue::from_pair(disp, raw));
            }
        }
        if let Some(obj) = resolved.record.as_object() {
            for k in obj.keys() {
                if (k.starts_with("u_") || k.starts_with("x_"))
                    && let Some((disp, raw)) = extract_field_pair(&resolved.record, k)
                {
                    custom_fields.insert(k.clone(), FieldValue::from_pair(disp, raw));
                }
            }
        }
    }

    // 2. Build composite `/api/now/batch` sub-requests
    let mut batch_reqs = Vec::new();
    let sys_id = &resolved.sys_id;

    if !args.no_journal {
        let url = format!(
            "/api/now/table/sys_journal_field?sysparm_query=element_id={sys_id}^elementINcomments,work_notes^ORDERBYsys_created_on&sysparm_display_value=all&sysparm_fields=sys_id,element,value,sys_created_on,sys_created_by&sysparm_limit=200"
        );
        batch_reqs.push(BatchGetSubRequest::new("journal", url));
    }

    // Service Catalog variables (`sc_item_option_mtom`) for `sc_req_item` or `sc_task`
    let ritm_sys_id = if resolved.table == "sc_req_item" {
        Some(resolved.sys_id.clone())
    } else if resolved.table == "sc_task" {
        extract_field_value(&resolved.record, "request_item")
    } else {
        None
    };

    if let Some(ritm_id) = &ritm_sys_id {
        let url = format!(
            "/api/now/table/sc_item_option_mtom?sysparm_query=request_item={ritm_id}^ORDERBYsc_item_option.order&sysparm_display_value=all&sysparm_fields=sc_item_option.item_option_new,sc_item_option.value&sysparm_limit=100"
        );
        batch_reqs.push(BatchGetSubRequest::new("catalog_vars", url));
    }

    if !args.no_related {
        let children_url = format!(
            "/api/now/table/task?sysparm_query=parent={sys_id}^ORrequest_item={sys_id}^ORDERBYsys_created_on&sysparm_display_value=all&sysparm_fields=sys_id,number,sys_class_name,state,short_description,assigned_to&sysparm_limit=50"
        );
        batch_reqs.push(BatchGetSubRequest::new("child_tasks", children_url));

        let approvals_url = format!(
            "/api/now/table/sysapproval_approver?sysparm_query=sysapproval={sys_id}^ORdocument_id={sys_id}^ORDERBYsys_created_on&sysparm_display_value=all&sysparm_fields=sys_id,approver,state,comments,sys_updated_on&sysparm_limit=50"
        );
        batch_reqs.push(BatchGetSubRequest::new("approvals", approvals_url));

        let ci_url = format!(
            "/api/now/table/task_ci?sysparm_query=task={sys_id}&sysparm_display_value=all&sysparm_fields=ci_item&sysparm_limit=50"
        );
        batch_reqs.push(BatchGetSubRequest::new("impacted_cis", ci_url));
    }

    let attachments_url = format!(
        "/api/now/table/sys_attachment?sysparm_query=table_sys_id={sys_id}^ORDERBYsys_created_on&sysparm_display_value=all&sysparm_fields=sys_id,file_name,content_type,size_bytes,sys_created_by,sys_created_on&sysparm_limit=100"
    );
    batch_reqs.push(BatchGetSubRequest::new("attachments", attachments_url));

    // Batch is an optimization (ADR-0003 amendment): skipped when the capability record says it
    // doesn't work here, and its failures are remembered.
    use crate::capabilities::{CapSource, CapState, Capability, CapabilityRecord};
    let try_batch = crate::capabilities::state(cache, Capability::BatchApi).worth_trying();
    let (batch_resp, batch_path) = client
        .get_all(
            &format!("dossier-{}", resolved.number),
            &batch_reqs,
            try_batch,
        )
        .await?;
    match &batch_path {
        crate::client::BatchPath::Batch => CapabilityRecord::observe(
            cache,
            Capability::BatchApi,
            CapState::Available,
            CapSource::Observed,
            Some(200),
            None,
        ),
        crate::client::BatchPath::Fallback(failure) => {
            if let Some((state, hint)) = failure.persistent {
                CapabilityRecord::observe(
                    cache,
                    Capability::BatchApi,
                    state,
                    CapSource::Observed,
                    failure.http_status,
                    Some(hint),
                );
            }
        }
        crate::client::BatchPath::Skipped => {}
    }
    let mut sections: BTreeMap<String, SectionStatus> = BTreeMap::new();
    for sub in &batch_resp.serviced_requests {
        sections.insert(sub.id.clone(), section_status(sub));
    }

    let mut acl_warnings = Vec::new();

    // 3. Decode Activity Stream (`journal`) with graceful 403 inline fallback
    let activity_stream = if args.no_journal {
        ActivityStreamSection {
            entries: Vec::new(),
            degraded_inline_fallback: false,
            acl_note: None,
        }
    } else if let Some(sub) = batch_resp.get("journal") {
        if sub.is_success() {
            let val: Value = sub.decode_json().unwrap_or_default();
            let entries = parse_journal_entries(&val);
            ActivityStreamSection {
                entries,
                degraded_inline_fallback: false,
                acl_note: None,
            }
        } else if sub.is_forbidden() {
            let note = "sys_journal_field returned 403 Forbidden; fell back to inline journal fields on ticket record.".to_string();
            acl_warnings.push(note.clone());
            let entries = parse_inline_journal_fallback(&resolved.record);
            ActivityStreamSection {
                entries,
                degraded_inline_fallback: true,
                acl_note: Some(note),
            }
        } else {
            ActivityStreamSection {
                entries: parse_inline_journal_fallback(&resolved.record),
                degraded_inline_fallback: true,
                acl_note: Some(format!(
                    "sys_journal_field returned HTTP {}; fell back to inline journal fields.",
                    sub.status_code
                )),
            }
        }
    } else {
        ActivityStreamSection {
            entries: Vec::new(),
            degraded_inline_fallback: false,
            acl_note: None,
        }
    };

    // 4. Decode Service Catalog Variables (`catalog_vars`)
    let mut catalog_variables = Vec::new();
    if let Some(sub) = batch_resp.get("catalog_vars") {
        if sub.is_success() {
            if let Ok(val) = sub.decode_json::<Value>()
                && let Some(rows) = val.get("result").and_then(Value::as_array)
            {
                for row in rows {
                    let question = extract_field_display(row, "sc_item_option.item_option_new");
                    let answer = extract_field_display(row, "sc_item_option.value");
                    if let (Some(q), Some(a)) = (question, answer)
                        && !q.is_empty()
                        && !a.is_empty()
                    {
                        catalog_variables.push(CatalogVariable {
                            question: q,
                            value: a,
                        });
                    }
                }
            }
        } else if sub.is_forbidden() {
            acl_warnings.push(
                "sc_item_option_mtom (catalog variables) returned 403 Forbidden.".to_string(),
            );
        }
    }

    // 5. Decode Related Hierarchy, Approvals, and Impacted CIs
    let mut child_tasks = Vec::new();
    let mut approvals = Vec::new();
    let mut impacted_cis = Vec::new();

    if !args.no_related {
        if let Some(sub) = batch_resp.get("child_tasks")
            && sub.is_success()
            && let Ok(val) = sub.decode_json::<Value>()
            && let Some(rows) = val.get("result").and_then(Value::as_array)
        {
            for row in rows {
                if let (Some(c_sys_id), Some(c_num)) = (
                    extract_field_value(row, "sys_id"),
                    extract_field_display(row, "number"),
                ) {
                    child_tasks.push(RelatedTaskSummary {
                        number: c_num,
                        table: extract_field_value(row, "sys_class_name")
                            .unwrap_or_else(|| "task".to_string()),
                        sys_id: c_sys_id,
                        state: extract_field_display(row, "state")
                            .unwrap_or_else(|| "Unknown".to_string()),
                        short_description: extract_field_display(row, "short_description")
                            .unwrap_or_default(),
                        assigned_to: extract_field_display(row, "assigned_to"),
                    });
                }
            }
        }

        if let Some(sub) = batch_resp.get("approvals") {
            if sub.is_success() {
                if let Ok(val) = sub.decode_json::<Value>()
                    && let Some(rows) = val.get("result").and_then(Value::as_array)
                {
                    for row in rows {
                        if let Some(a_sys_id) = extract_field_value(row, "sys_id") {
                            approvals.push(ApprovalSummary {
                                sys_id: a_sys_id,
                                approver: extract_field_display(row, "approver")
                                    .unwrap_or_else(|| "Unknown".to_string()),
                                state: extract_field_display(row, "state")
                                    .unwrap_or_else(|| "Unknown".to_string()),
                                updated_on: extract_field_display(row, "sys_updated_on")
                                    .unwrap_or_default(),
                                comments: extract_field_display(row, "comments"),
                            });
                        }
                    }
                }
            } else if sub.is_forbidden() {
                acl_warnings.push("sysapproval_approver returned 403 Forbidden.".to_string());
            }
        }

        if let Some(sub) = batch_resp.get("impacted_cis")
            && sub.is_success()
            && let Ok(val) = sub.decode_json::<Value>()
            && let Some(rows) = val.get("result").and_then(Value::as_array)
        {
            for row in rows {
                if let Some(ci_name) = extract_field_display(row, "ci_item")
                    && !impacted_cis.contains(&ci_name)
                {
                    impacted_cis.push(ci_name);
                }
            }
        }
    }

    let related = RelatedSection {
        parent: extract_field_display(&resolved.record, "parent"),
        request: extract_field_display(&resolved.record, "request"),
        request_item: extract_field_display(&resolved.record, "request_item"),
        child_tasks,
        approvals,
        impacted_cis,
    };

    // 6. Decode Attachments (`sys_attachment`)
    let mut attachments = Vec::new();
    if let Some(sub) = batch_resp.get("attachments") {
        if sub.is_success() {
            if let Ok(val) = sub.decode_json::<Value>()
                && let Some(rows) = val.get("result").and_then(Value::as_array)
            {
                for row in rows {
                    if let (Some(att_id), Some(file_name)) = (
                        extract_field_value(row, "sys_id"),
                        extract_field_display(row, "file_name"),
                    ) {
                        let size_bytes = extract_field_value(row, "size_bytes")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        attachments.push(AttachmentMeta {
                            sys_id: att_id,
                            file_name,
                            content_type: extract_field_display(row, "content_type")
                                .unwrap_or_else(|| "application/octet-stream".to_string()),
                            size_bytes,
                            created_by: extract_field_display(row, "sys_created_by")
                                .unwrap_or_default(),
                            created_on: extract_field_display(row, "sys_created_on")
                                .unwrap_or_default(),
                        });
                    }
                }
            }
        } else if sub.is_forbidden() {
            acl_warnings.push("sys_attachment returned 403 Forbidden.".to_string());
        }
    }

    let degraded: Vec<String> = sections
        .iter()
        .filter(|(_, st)| st.status != "ok")
        .map(|(name, _)| name.clone())
        .collect();
    for name in &degraded {
        let st = &sections[name];
        let note = format!(
            "{name}: {} ({})",
            st.status,
            st.detail.as_deref().unwrap_or("no detail")
        );
        if st.status != "restricted"
            && !acl_warnings
                .iter()
                .any(|w| w.starts_with(&format!("{name}:")))
        {
            acl_warnings.push(note);
        }
    }

    Ok(TicketDossier {
        number: resolved.number,
        table: resolved.table,
        sys_id: resolved.sys_id,
        ui_url,
        core_fields,
        custom_fields,
        catalog_variables,
        activity_stream,
        related,
        attachments,
        acl_warnings,
        sections,
        degraded,
    })
}

fn parse_journal_entries(val: &Value) -> Vec<JournalEntry> {
    let mut entries = Vec::new();
    if let Some(rows) = val.get("result").and_then(Value::as_array) {
        for row in rows {
            let Some(body) = extract_field_display(row, "value") else {
                continue;
            };
            let element =
                extract_field_value(row, "element").unwrap_or_else(|| "comments".to_string());
            let author = extract_field_display(row, "sys_created_by")
                .unwrap_or_else(|| "system".to_string());
            let timestamp = extract_field_display(row, "sys_created_on").unwrap_or_default();
            entries.push(JournalEntry {
                element,
                author,
                timestamp,
                body,
            });
        }
    }
    entries
}

fn parse_inline_journal_fallback(record: &Value) -> Vec<JournalEntry> {
    let mut entries = Vec::new();
    for (field, element) in [
        ("comments_and_work_notes", "comments_and_work_notes"),
        ("comments", "comments"),
        ("work_notes", "work_notes"),
    ] {
        if let Some(raw_text) = extract_field_display(record, field)
            && !raw_text.trim().is_empty()
        {
            // ServiceNow inline journal blocks are separated by double newlines (`\n\n`)
            for block in raw_text.split("\n\n") {
                let trimmed = block.trim();
                if trimmed.is_empty() {
                    continue;
                }
                entries.push(JournalEntry {
                    element: element.to_string(),
                    author: "inline".to_string(),
                    timestamp: String::new(),
                    body: trimmed.to_string(),
                });
            }
            if !entries.is_empty() {
                break;
            }
        }
    }
    entries
}

/// Formats one or more [`TicketDossier`] items according to `format`.
pub fn format_ticket_dossiers(dossiers: &[TicketDossier], format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => {
            if dossiers.len() == 1 {
                serde_json::to_string_pretty(&dossiers[0]).unwrap_or_default()
            } else {
                serde_json::to_string_pretty(dossiers).unwrap_or_default()
            }
        }
        ResolvedOutputFormat::Yaml => {
            if dossiers.len() == 1 {
                serde_yaml::to_string(&dossiers[0]).unwrap_or_default()
            } else {
                serde_yaml::to_string(dossiers).unwrap_or_default()
            }
        }
        ResolvedOutputFormat::Md => dossiers
            .iter()
            .map(format_single_dossier_md)
            .collect::<Vec<_>>()
            .join("\n---\n\n"),
        ResolvedOutputFormat::TerminalDossier | ResolvedOutputFormat::Table => dossiers
            .iter()
            .map(format_single_dossier_terminal)
            .collect::<Vec<_>>()
            .join("\n================================================================================\n\n"),
    }
}

fn format_single_dossier_md(d: &TicketDossier) -> String {
    let mut out = String::new();
    let short_desc = d
        .core_fields
        .get("short_description")
        .map(|f| f.display_value.as_str())
        .unwrap_or("(no short description)");
    out.push_str(&format!(
        "# {} — {}\n\n",
        d.number,
        crate::untrusted::inline(short_desc)
    ));
    if !d.degraded.is_empty() {
        let parts: Vec<String> = d
            .degraded
            .iter()
            .map(|name| format!("{name} {}", d.sections[name].status.replace('_', " ")))
            .collect();
        out.push_str(&format!("⚠ Partial dossier: {}.\n\n", parts.join("; ")));
    }
    out.push_str(&format!(
        "- **Table**: `{}` (`sys_id={}`)\n",
        d.table, d.sys_id
    ));
    out.push_str(&format!("- **URL**: {}\n\n", d.ui_url));

    out.push_str("## Core Fields\n\n");
    for (k, v) in &d.core_fields {
        if k == "description" || k == "close_notes" {
            continue;
        }
        if let Some(raw) = &v.raw_value {
            out.push_str(&format!("- **`{k}`**: {} (`{raw}`)\n", v.display_value));
        } else {
            out.push_str(&format!("- **`{k}`**: {}\n", v.display_value));
        }
    }

    if let Some(desc) = d.core_fields.get("description") {
        out.push_str(&format!("\n### Description\n\n{}\n", desc.display_value));
    }
    if let Some(notes) = d.core_fields.get("close_notes") {
        out.push_str(&format!("\n### Close Notes\n\n{}\n", notes.display_value));
    }

    if !d.custom_fields.is_empty() {
        out.push_str("\n## Custom Fields (`u_*` / `x_*`)\n\n");
        for (k, v) in &d.custom_fields {
            if let Some(raw) = &v.raw_value {
                out.push_str(&format!("- **`{k}`**: {} (`{raw}`)\n", v.display_value));
            } else {
                out.push_str(&format!("- **`{k}`**: {}\n", v.display_value));
            }
        }
    }

    if !d.catalog_variables.is_empty() {
        out.push_str("\n## Service Catalog Variables\n\n");
        for var in &d.catalog_variables {
            out.push_str(&format!("- **{}**: {}\n", var.question, var.value));
        }
    }

    if d.related.parent.is_some()
        || d.related.request.is_some()
        || d.related.request_item.is_some()
        || !d.related.child_tasks.is_empty()
        || !d.related.approvals.is_empty()
        || !d.related.impacted_cis.is_empty()
    {
        out.push_str("\n## Related Records & Approvals\n\n");
        if let Some(p) = &d.related.parent {
            out.push_str(&format!("- **Parent**: {p}\n"));
        }
        if let Some(r) = &d.related.request {
            out.push_str(&format!("- **Request**: {r}\n"));
        }
        if let Some(ri) = &d.related.request_item {
            out.push_str(&format!("- **Requested Item**: {ri}\n"));
        }
        if !d.related.impacted_cis.is_empty() {
            out.push_str(&format!(
                "- **Impacted CIs**: {}\n",
                d.related.impacted_cis.join(", ")
            ));
        }
        for child in &d.related.child_tasks {
            out.push_str(&format!(
                "- **Child Task `{}`** (`{}`, {}): {}\n",
                child.number, child.table, child.state, child.short_description
            ));
        }
        for app in &d.related.approvals {
            out.push_str(&format!(
                "- **Approval** — {}: `{}` ({})\n",
                app.approver, app.state, app.updated_on
            ));
        }
    }

    if !d.attachments.is_empty() {
        out.push_str("\n## Attachments\n\n");
        for att in &d.attachments {
            out.push_str(&format!(
                "- **`{}`** ({} bytes, `{}`, `sys_id={}`)\n",
                att.file_name, att.size_bytes, att.content_type, att.sys_id
            ));
        }
    }

    out.push_str("\n## Activity Stream (`comments` & `work_notes`)\n\n");
    if let Some(note) = &d.activity_stream.acl_note {
        out.push_str(&format!("> Note: {note}\n\n"));
    }
    if d.activity_stream.entries.is_empty() {
        out.push_str("_No journal entries recorded._\n");
    } else {
        for entry in &d.activity_stream.entries {
            if entry.timestamp.is_empty() {
                out.push_str(&format!("### [{}]\n{}\n\n", entry.element, entry.body));
            } else {
                out.push_str(&format!(
                    "### {} — `{}` ({})\n{}\n\n",
                    entry.timestamp, entry.author, entry.element, entry.body
                ));
            }
        }
    }

    out
}

fn format_single_dossier_terminal(d: &TicketDossier) -> String {
    let mut out = String::new();
    let short_desc = d
        .core_fields
        .get("short_description")
        .map(|f| f.display_value.as_str())
        .unwrap_or("(no short description)");
    out.push_str(&format!(
        "{} [{}] — {}\n",
        osc8_link(&d.ui_url, &d.number),
        d.table,
        short_desc
    ));
    out.push_str(&format!("URL:    {}\n", osc8_link(&d.ui_url, &d.ui_url)));
    out.push_str(&format!("sys_id: {}\n\n", d.sys_id));

    let mut kv_table = Table::new();
    kv_table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["FIELD", "VALUE"]);

    for (k, v) in &d.core_fields {
        if k == "description" || k == "close_notes" || k == "short_description" {
            continue;
        }
        kv_table.add_row(vec![Cell::new(k), styled_table_cell(k, &v.display_value)]);
    }
    for (k, v) in &d.custom_fields {
        kv_table.add_row(vec![Cell::new(k), styled_table_cell(k, &v.display_value)]);
    }
    out.push_str(&kv_table.to_string());
    out.push('\n');

    if let Some(desc) = d.core_fields.get("description") {
        out.push_str(&format!("\nDESCRIPTION:\n{}\n", desc.display_value));
    }
    if let Some(notes) = d.core_fields.get("close_notes") {
        out.push_str(&format!("\nCLOSE NOTES:\n{}\n", notes.display_value));
    }

    if !d.catalog_variables.is_empty() {
        out.push_str("\nCATALOG VARIABLES:\n");
        for var in &d.catalog_variables {
            out.push_str(&format!("  - {}: {}\n", var.question, var.value));
        }
    }

    if !d.related.child_tasks.is_empty() || !d.related.approvals.is_empty() {
        out.push_str("\nRELATED RECORDS & APPROVALS:\n");
        for child in &d.related.child_tasks {
            out.push_str(&format!(
                "  - [Task] {} ({}): {}\n",
                child.number, child.state, child.short_description
            ));
        }
        for app in &d.related.approvals {
            out.push_str(&format!(
                "  - [Approval] {}: {} ({})\n",
                app.approver, app.state, app.updated_on
            ));
        }
    }

    if !d.attachments.is_empty() {
        out.push_str("\nATTACHMENTS:\n");
        for att in &d.attachments {
            out.push_str(&format!(
                "  - {} ({} bytes, sys_id={})\n",
                att.file_name, att.size_bytes, att.sys_id
            ));
        }
    }

    out.push_str("\nACTIVITY STREAM:\n");
    if let Some(note) = &d.activity_stream.acl_note {
        out.push_str(&format!("  (Note: {note})\n"));
    }
    if d.activity_stream.entries.is_empty() {
        out.push_str("  (no journal entries)\n");
    } else {
        for entry in &d.activity_stream.entries {
            out.push_str(&format!(
                "  [{} | {} | {}]\n  {}\n\n",
                entry.timestamp, entry.author, entry.element, entry.body
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn assembles_batch_ticket_dossier_with_custom_fields_catalog_vars_and_journal() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        // 1. Resolve `RITM0049210` on `sc_req_item`
        Mock::given(method("GET"))
            .and(path("/api/now/table/sc_req_item"))
            .and(query_param("sysparm_query", "number=RITM0049210"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "ritm_sys_1", "display_value": "ritm_sys_1" },
                    "number": { "value": "RITM0049210", "display_value": "RITM0049210" },
                    "sys_class_name": { "value": "sc_req_item", "display_value": "Requested Item" },
                    "state": { "value": "2", "display_value": "Work in Progress" },
                    "short_description": { "value": "Provision AWS Sandbox", "display_value": "Provision AWS Sandbox" },
                    "u_cost_center": { "value": "CC-900", "display_value": "Engineering CC-900" }
                }]
            })))
            .mount(&server)
            .await;

        // 2. Composite `/api/now/batch` sub-responses
        let journal_b64 = BASE64_STANDARD.encode(
            json!({
                "result": [{
                    "sys_id": { "value": "j1", "display_value": "j1" },
                    "element": { "value": "comments", "display_value": "Additional comments" },
                    "value": { "value": "Request approved by manager.", "display_value": "Request approved by manager." },
                    "sys_created_by": { "value": "alice", "display_value": "Alice Smith" },
                    "sys_created_on": { "value": "2026-10-22 14:00:00", "display_value": "2026-10-22 14:00:00" }
                }]
            })
            .to_string(),
        );
        let vars_b64 = BASE64_STANDARD.encode(
            json!({
                "result": [{
                    "sc_item_option.item_option_new": { "value": "q1", "display_value": "AWS Region" },
                    "sc_item_option.value": { "value": "us-east-1", "display_value": "us-east-1" }
                }]
            })
            .to_string(),
        );
        let empty_b64 = BASE64_STANDARD.encode(json!({ "result": [] }).to_string());

        Mock::given(method("POST"))
            .and(path("/api/now/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "batch_request_id": "dossier-RITM0049210",
                "serviced_requests": [
                    { "id": "journal", "status_code": 200, "body": journal_b64 },
                    { "id": "catalog_vars", "status_code": 200, "body": vars_b64 },
                    { "id": "child_tasks", "status_code": 200, "body": empty_b64 },
                    { "id": "approvals", "status_code": 200, "body": empty_b64 },
                    { "id": "impacted_cis", "status_code": 200, "body": empty_b64 },
                    { "id": "attachments", "status_code": 200, "body": empty_b64 }
                ]
            })))
            .mount(&server)
            .await;

        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let args = ShowArgs {
            tickets: vec!["RITM0049210".to_string()],
            all_fields: false,
            fields: vec![],
            no_journal: false,
            no_related: false,
        };

        let dossier = assemble_ticket_dossier(&client, &cache, &args, "RITM0049210")
            .await
            .expect("assemble dossier");

        assert_eq!(dossier.number, "RITM0049210");
        assert_eq!(
            dossier
                .custom_fields
                .get("u_cost_center")
                .map(|f| f.display_value.as_str()),
            Some("Engineering CC-900")
        );
        assert_eq!(dossier.catalog_variables.len(), 1);
        assert_eq!(dossier.catalog_variables[0].question, "AWS Region");
        assert_eq!(dossier.catalog_variables[0].value, "us-east-1");
        assert_eq!(dossier.activity_stream.entries.len(), 1);
        assert!(!dossier.activity_stream.degraded_inline_fallback);
    }

    #[tokio::test]
    async fn degrades_gracefully_to_inline_comments_when_sys_journal_field_returns_403() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .and(query_param("sysparm_query", "number=INC0010042"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "inc_sys_42", "display_value": "inc_sys_42" },
                    "number": { "value": "INC0010042", "display_value": "INC0010042" },
                    "state": { "value": "2", "display_value": "In Progress" },
                    "short_description": { "value": "VPN timeout", "display_value": "VPN timeout" },
                    "comments_and_work_notes": {
                        "value": "2026-10-22 10:00:00 - Bob (Additional comments)\nInvestigating gateway logs.",
                        "display_value": "2026-10-22 10:00:00 - Bob (Additional comments)\nInvestigating gateway logs."
                    }
                }]
            })))
            .mount(&server)
            .await;

        let empty_b64 = BASE64_STANDARD.encode(json!({ "result": [] }).to_string());
        let forbidden_b64 =
            BASE64_STANDARD.encode(json!({ "error": { "message": "ACL Denied" } }).to_string());

        Mock::given(method("POST"))
            .and(path("/api/now/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "batch_request_id": "dossier-INC0010042",
                "serviced_requests": [
                    { "id": "journal", "status_code": 403, "body": forbidden_b64 },
                    { "id": "child_tasks", "status_code": 200, "body": empty_b64 },
                    { "id": "approvals", "status_code": 200, "body": empty_b64 },
                    { "id": "impacted_cis", "status_code": 200, "body": empty_b64 },
                    { "id": "attachments", "status_code": 200, "body": empty_b64 }
                ]
            })))
            .mount(&server)
            .await;

        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let args = ShowArgs {
            tickets: vec!["INC0010042".to_string()],
            all_fields: false,
            fields: vec![],
            no_journal: false,
            no_related: false,
        };

        let dossier = assemble_ticket_dossier(&client, &cache, &args, "INC0010042")
            .await
            .expect("assemble dossier with 403 journal");

        assert!(dossier.activity_stream.degraded_inline_fallback);
        assert_eq!(dossier.activity_stream.entries.len(), 1);
        assert!(
            dossier.activity_stream.entries[0]
                .body
                .contains("Investigating gateway logs.")
        );
    }

    #[tokio::test]
    async fn falls_back_to_concurrent_get_requests_when_batch_api_is_restricted() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .and(query_param("sysparm_query", "number=INC0099999"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "inc_sys_99", "display_value": "inc_sys_99" },
                    "number": { "value": "INC0099999", "display_value": "INC0099999" },
                    "state": { "value": "2", "display_value": "In Progress" },
                    "short_description": { "value": "Batch API restricted test", "display_value": "Batch API restricted test" }
                }]
            })))
            .mount(&server)
            .await;

        // Simulate `/api/now/batch` being restricted/unavailable (HTTP 403 or 400)
        Mock::given(method("POST"))
            .and(path("/api/now/batch"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": { "message": "Access to /api/now/batch is restricted" }
            })))
            .mount(&server)
            .await;

        // Individual GET sub-requests succeed via concurrent fallback
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_journal_field"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "j99", "display_value": "j99" },
                    "element": { "value": "comments", "display_value": "Additional comments" },
                    "value": { "value": "Fetched via concurrent GET fallback.", "display_value": "Fetched via concurrent GET fallback." },
                    "sys_created_by": { "value": "eric", "display_value": "Eric Sabetti" },
                    "sys_created_on": { "value": "2026-10-23 11:55:00", "display_value": "2026-10-23 11:55:00" }
                }]
            })))
            .mount(&server)
            .await;

        for sub_path in [
            "/api/now/table/task",
            "/api/now/table/sysapproval_approver",
            "/api/now/table/task_ci",
            "/api/now/table/sys_attachment",
        ] {
            Mock::given(method("GET"))
                .and(path(sub_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
                .mount(&server)
                .await;
        }

        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let args = ShowArgs {
            tickets: vec!["INC0099999".to_string()],
            all_fields: false,
            fields: vec![],
            no_journal: false,
            no_related: false,
        };

        let dossier = assemble_ticket_dossier(&client, &cache, &args, "INC0099999")
            .await
            .expect("assemble dossier via concurrent GET fallback");

        assert_eq!(dossier.number, "INC0099999");
        assert!(!dossier.activity_stream.degraded_inline_fallback);
        assert_eq!(dossier.activity_stream.entries.len(), 1);
        assert_eq!(
            dossier.activity_stream.entries[0].body,
            "Fetched via concurrent GET fallback."
        );
    }
}
