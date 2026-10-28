use crate::auth::resolve_current_identity;
use crate::cache::{CachedIdentity, InstanceCache};
use crate::cli::{ApprovalActionArgs, ApprovalListArgs, CatalogOrderArgs};
use crate::client::write_gate::{ResolvedField, Target, VerifiedMutation};
use crate::client::{ReadOnlyClient, WritePermit, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::mutate::{
    FieldDiff, MutationReport, parse_key_value_pair, resolve_user_reference, run_gate, shell_quote,
};
use crate::output::{ResolvedOutputFormat, styled_table_cell};
use crate::query::{DYNAMIC_ME_SYS_ID, EncodedQuery};
use crate::resolve::{is_sys_id, resolve_ticket};
use crate::resolve_value::ResolvedValue;
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub sys_id: String,
    pub state: String,
    pub approver: String,
    pub target_ticket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_table: Option<String>,
    pub created_on: String,
    pub updated_on: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
    /// Raw `state` value (e.g. `requested`), used to select approve/reject targets.
    #[serde(skip)]
    pub state_value: Option<String>,
    /// Raw `approver` sys_id, used to select approve/reject targets.
    #[serde(skip)]
    pub approver_sys_id: Option<String>,
    /// Display value of the approval `group`, when the approval is group-linked.
    #[serde(skip)]
    pub group: Option<String>,
    /// `group.assignment_group` sys_id, used to match group-linked approvals against `@my-groups`.
    #[serde(skip)]
    pub group_assignment_group: Option<String>,
}

impl ApprovalItem {
    pub(crate) fn is_requested(&self) -> bool {
        self.state_value
            .as_deref()
            .unwrap_or(&self.state)
            .eq_ignore_ascii_case("requested")
    }

    /// True when this approval is assigned to `identity` directly or through one of its groups (APR-4).
    pub(crate) fn is_linked_to(&self, identity: &CachedIdentity) -> bool {
        self.approver_sys_id.as_deref() == Some(identity.sys_id.as_str())
            || self
                .group_assignment_group
                .as_deref()
                .is_some_and(|ag| identity.groups.iter().any(|g| g.sys_id == ag))
    }

    pub(crate) fn describe(&self) -> String {
        let via = self
            .group
            .as_deref()
            .map(|g| format!(" via group {g}"))
            .unwrap_or_default();
        format!(
            "{} — {}{via} [{}] on {}",
            self.sys_id, self.approver, self.state, self.target_ticket
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalsEnvelope {
    pub count: usize,
    pub query: String,
    pub items: Vec<ApprovalItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogItemSummary {
    pub sys_id: String,
    pub name: String,
    pub short_description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogVariableSpec {
    pub name: String,
    pub label: String,
    pub field_type: String,
    pub mandatory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogItemDetail {
    pub sys_id: String,
    pub name: String,
    pub short_description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<CatalogVariableSpec>,
}

/// Executes `sncfr approvals list`.
pub async fn execute_approvals_list(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &ApprovalListArgs,
) -> Result<ApprovalsEnvelope, SncfrError> {
    let mut eq = EncodedQuery::new();
    if !args.state.trim().is_empty() && !args.state.eq_ignore_ascii_case("all") {
        eq.equals("state", args.state.trim());
    }
    if !args.all_users {
        if let Ok(identity) = resolve_current_identity(client, cache, false).await {
            eq.equals("approver", &identity.sys_id);
        } else {
            eq.dynamic("approver", DYNAMIC_ME_SYS_ID);
        }
    }
    eq.order_by_desc("sys_created_on");
    let query_str = eq.build();

    let resp: Value = client
        .get_json(
            "/api/now/table/sysapproval_approver",
            &[
                ("sysparm_query", query_str.as_str()),
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "sys_id,state,approver,sysapproval,document_id,source_table,comments,sys_created_on,sys_updated_on",
                ),
                ("sysparm_limit", "50"),
            ],
        )
        .await?;

    let items = parse_approval_rows(&resp);
    Ok(ApprovalsEnvelope {
        count: items.len(),
        query: query_str,
        items,
    })
}

/// Executes `sncfr approvals show <approval_or_ticket>`.
pub async fn execute_approvals_show(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    approval_or_ticket: &str,
) -> Result<ApprovalsEnvelope, SncfrError> {
    let trimmed = approval_or_ticket.trim();
    let query_str = if is_sys_id(trimmed) {
        format!("sys_id={trimmed}^ORsysapproval={trimmed}^ORdocument_id={trimmed}")
    } else {
        let resolved = resolve_ticket(client, cache, trimmed).await?;
        format!(
            "sysapproval={}^ORdocument_id={}^ORDERBYDESCsys_created_on",
            resolved.sys_id, resolved.sys_id
        )
    };

    let resp: Value = client
        .get_json(
            "/api/now/table/sysapproval_approver",
            &[
                ("sysparm_query", query_str.as_str()),
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "sys_id,state,approver,group,group.assignment_group,sysapproval,document_id,source_table,comments,sys_created_on,sys_updated_on",
                ),
                ("sysparm_limit", "25"),
            ],
        )
        .await?;

    let items = parse_approval_rows(&resp);
    if items.is_empty() {
        return Err(SncfrError::NotFound {
            identifier: trimmed.to_string(),
            table: Some("sysapproval_approver".to_string()),
        });
    }

    Ok(ApprovalsEnvelope {
        count: items.len(),
        query: query_str,
        items,
    })
}

/// Executes `sncfr approvals approve` (`approve = true`) or `sncfr approvals reject` (`approve = false`).
pub async fn execute_approval_action(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &ApprovalActionArgs,
    approve: bool,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let show_env = execute_approvals_show(&client, cache, &args.approval_or_ticket).await?;
    let identity = resolve_current_identity(&client, cache, false).await?;
    let target = crate::references::select_approval_target(
        &args.approval_or_ticket,
        &show_env.items,
        &identity,
    )?;

    let new_state_val = if approve { "approved" } else { "rejected" };
    let new_state_disp = if approve { "Approved" } else { "Rejected" };
    let op_name = if approve { "approve" } else { "reject" };

    let mut diffs = vec![FieldDiff {
        field: "state".to_string(),
        before_display: Some(target.state.clone()),
        before_value: Some(target.state.to_ascii_lowercase()),
        after_display: new_state_disp.to_string(),
        after_value: new_state_val.to_string(),
        ..Default::default()
    }];

    let mut fields: Vec<ResolvedField> = vec![(
        "state".to_string(),
        new_state_val.to_string(),
        ResolvedValue::verified(
            new_state_val.to_string(),
            Some(new_state_disp.to_string()),
            None,
        ),
    )];
    if let Some(comments) = &args.comments {
        diffs.push(FieldDiff {
            field: "comments".to_string(),
            before_display: target.comments.clone(),
            before_value: target.comments.clone(),
            after_display: comments.clone(),
            after_value: comments.clone(),
            source: Some("input".to_string()),
            status: Some("n/a (free text)".to_string()),
            ..Default::default()
        });
        fields.push((
            "comments".to_string(),
            comments.clone(),
            ResolvedValue::text(comments),
        ));
    }

    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();
    let ui_url = format!(
        "{base_url}/nav_to.do?uri=sysapproval_approver.do?sys_id={}",
        target.sys_id
    );

    let mut cmd_parts = vec![
        "sncfr".to_string(),
        "approvals".to_string(),
        op_name.to_string(),
        shell_quote(&target.sys_id),
    ];
    if let Some(comments) = &args.comments {
        cmd_parts.push("--comments".to_string());
        cmd_parts.push(shell_quote(comments));
    }
    cmd_parts.push("--write".to_string());

    let mutation = VerifiedMutation::record(
        Target::patch_record("sysapproval_approver", &target.sys_id)?,
        &fields,
    );
    let gate = run_gate(client, permit, vec![mutation]).await?;
    let mut report = MutationReport {
        operation: op_name.to_string(),
        ticket: Some(target.target_ticket),
        table: "sysapproval_approver".to_string(),
        sys_id: Some(target.sys_id.clone()),
        ui_url: Some(ui_url),
        diffs,
        commit_command: Some(cmd_parts.join(" ")),
        ..Default::default()
    };
    gate.fill(&mut report);
    Ok(report)
}

fn parse_approval_rows(resp: &Value) -> Vec<ApprovalItem> {
    let mut items = Vec::new();
    if let Some(rows) = resp.get("result").and_then(Value::as_array) {
        for row in rows {
            let Some(sys_id) = extract_field_value(row, "sys_id") else {
                continue;
            };
            let target_ticket = extract_field_display(row, "sysapproval")
                .or_else(|| extract_field_display(row, "document_id"))
                .unwrap_or_else(|| "(unknown)".to_string());
            items.push(ApprovalItem {
                sys_id,
                state: extract_field_display(row, "state").unwrap_or_else(|| "Unknown".to_string()),
                approver: extract_field_display(row, "approver")
                    .unwrap_or_else(|| "Unknown".to_string()),
                target_ticket,
                source_table: extract_field_display(row, "source_table"),
                created_on: extract_field_display(row, "sys_created_on").unwrap_or_default(),
                updated_on: extract_field_display(row, "sys_updated_on").unwrap_or_default(),
                comments: extract_field_display(row, "comments"),
                state_value: extract_field_value(row, "state"),
                approver_sys_id: extract_field_value(row, "approver"),
                group: extract_field_display(row, "group"),
                group_assignment_group: extract_field_value(row, "group.assignment_group"),
            });
        }
    }
    items
}

/// Executes `sncfr catalog search <query> [--limit <n>]`.
pub async fn execute_catalog_search(
    client: &ReadOnlyClient,
    query: &str,
    limit: u32,
) -> Result<Vec<CatalogItemSummary>, SncfrError> {
    let limit_str = limit.to_string();
    let mut items = Vec::new();

    if let Ok(resp) = client
        .get_json::<Value>(
            "/api/sn_sc/servicecatalog/items",
            &[
                ("sysparm_text", query),
                ("sysparm_limit", limit_str.as_str()),
            ],
        )
        .await
        && let Some(rows) = resp.get("result").and_then(Value::as_array)
    {
        for row in rows {
            if let (Some(sys_id), Some(name)) = (
                extract_field_value(row, "sys_id"),
                extract_field_display(row, "name"),
            ) {
                items.push(CatalogItemSummary {
                    sys_id,
                    name,
                    short_description: extract_field_display(row, "short_description")
                        .unwrap_or_default(),
                    category: extract_field_display(row, "category"),
                });
            }
        }
        return Ok(items);
    }

    // Fallback to `sc_cat_item` table query if Service Catalog REST API returns 403/404
    let q = format!("active=true^nameLIKE{query}^ORshort_descriptionLIKE{query}");
    let resp: Value = client
        .get_json(
            "/api/now/table/sc_cat_item",
            &[
                ("sysparm_query", q.as_str()),
                ("sysparm_limit", limit_str.as_str()),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "sys_id,name,short_description,category"),
            ],
        )
        .await?;

    if let Some(rows) = resp.get("result").and_then(Value::as_array) {
        for row in rows {
            if let (Some(sys_id), Some(name)) = (
                extract_field_value(row, "sys_id"),
                extract_field_display(row, "name"),
            ) {
                items.push(CatalogItemSummary {
                    sys_id,
                    name,
                    short_description: extract_field_display(row, "short_description")
                        .unwrap_or_default(),
                    category: extract_field_display(row, "category"),
                });
            }
        }
    }
    Ok(items)
}

/// Executes `sncfr catalog show <item_sys_id_or_name>`.
pub async fn execute_catalog_show(
    client: &ReadOnlyClient,
    item: &str,
) -> Result<CatalogItemDetail, SncfrError> {
    let trimmed = item.trim();
    let item_sys_id = if is_sys_id(trimmed) {
        trimmed.to_string()
    } else {
        let found = execute_catalog_search(client, trimmed, 5).await?;
        found
            .into_iter()
            .find(|i| i.name.eq_ignore_ascii_case(trimmed))
            .map(|i| i.sys_id)
            .ok_or_else(|| SncfrError::NotFound {
                identifier: trimmed.to_string(),
                table: Some("sc_cat_item".to_string()),
            })?
    };

    let path = format!("/api/sn_sc/servicecatalog/items/{item_sys_id}");
    let resp: Value = client.get_json(&path, &[]).await?;
    let res = resp.get("result").unwrap_or(&resp);

    let name = extract_field_display(res, "name").unwrap_or_else(|| item_sys_id.clone());
    let short_description = extract_field_display(res, "short_description").unwrap_or_default();
    let description = extract_field_display(res, "description");

    let mut variables = Vec::new();
    if let Some(vars) = res.get("variables").and_then(Value::as_array) {
        for v in vars {
            let Some(var_name) = v.get("name").and_then(Value::as_str) else {
                continue;
            };
            let label = v
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or(var_name)
                .to_string();
            let field_type = v
                .get("friendly_type")
                .or_else(|| v.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("string")
                .to_string();
            let mandatory = v.get("mandatory").and_then(Value::as_bool).unwrap_or(false);
            let default_value = v
                .get("value")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);

            let mut choices = Vec::new();
            if let Some(ch_arr) = v.get("choices").and_then(Value::as_array) {
                for ch in ch_arr {
                    let lbl = ch.get("label").and_then(Value::as_str).unwrap_or_default();
                    let val = ch.get("value").and_then(Value::as_str).unwrap_or_default();
                    if !val.is_empty() {
                        choices.push(format!("{lbl} ({val})"));
                    }
                }
            }

            variables.push(CatalogVariableSpec {
                name: var_name.to_string(),
                label,
                field_type,
                mandatory,
                default_value,
                choices,
            });
        }
    }

    Ok(CatalogItemDetail {
        sys_id: item_sys_id,
        name,
        short_description,
        description,
        variables,
    })
}

/// Executes `sncfr catalog order <item_sys_id> [--var k=v...] [--write]`.
pub async fn execute_catalog_order(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &CatalogOrderArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let detail = execute_catalog_show(&client, &args.item_sys_id).await?;
    let mut variables: Vec<ResolvedField> = Vec::new();
    let mut diffs = Vec::new();

    // Variable values are checked against the item's metadata in CAT-4; until then they are sent
    // as typed.
    for kv in &args.variables {
        let (k, v) = parse_key_value_pair(kv)?;
        diffs.push(FieldDiff {
            field: format!("var:{k}"),
            before_display: None,
            before_value: None,
            after_display: v.clone(),
            after_value: v.clone(),
            source: Some("input".to_string()),
            status: Some("n/a (free text)".to_string()),
            ..Default::default()
        });
        let value = ResolvedValue::text(&v);
        variables.push((k, v, value));
    }

    // Validate mandatory variables
    for var_spec in &detail.variables {
        if var_spec.mandatory
            && !variables.iter().any(|(name, _, _)| name == &var_spec.name)
            && var_spec.default_value.is_none()
        {
            return Err(SncfrError::Validation {
                message: format!(
                    "Missing mandatory catalog variable '{}' ({}) for item '{}'",
                    var_spec.name, var_spec.label, detail.name
                ),
                valid_choices: var_spec.choices.clone(),
                remediation: Some(format!(
                    "Pass `--var {}=<value>` (run `sncfr catalog show {}` to inspect variables).",
                    var_spec.name, detail.sys_id
                )),
            });
        }
    }

    let mut order_payload = json!({
        "sysparm_quantity": args.quantity.to_string(),
    });

    if let Some(req_for) = &args.requested_for {
        let (disp, user_sys_id, ref_source) =
            resolve_user_reference(&client, cache, req_for).await?;
        diffs.push(FieldDiff {
            field: "requested_for".to_string(),
            before_display: None,
            before_value: None,
            after_display: disp,
            after_value: user_sys_id.clone(),
            source: Some(ref_source),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        order_payload["sysparm_requested_for"] = Value::String(user_sys_id);
    }

    let mut cmd_parts = vec![
        "sncfr".to_string(),
        "catalog".to_string(),
        "order".to_string(),
        shell_quote(&detail.sys_id),
    ];
    for kv in &args.variables {
        cmd_parts.push("--var".to_string());
        cmd_parts.push(shell_quote(kv));
    }
    if args.quantity != 1 {
        cmd_parts.push("--quantity".to_string());
        cmd_parts.push(args.quantity.to_string());
    }
    if let Some(req_for) = &args.requested_for {
        cmd_parts.push("--requested-for".to_string());
        cmd_parts.push(shell_quote(req_for));
    }
    cmd_parts.push("--write".to_string());

    let mutation = VerifiedMutation::catalog_order(
        Target::catalog_order(&detail.sys_id)?,
        order_payload,
        &variables,
    );
    let gate = run_gate(client, permit, vec![mutation]).await?;
    let mut report = MutationReport {
        operation: "catalog_order".to_string(),
        ticket: Some(detail.name.clone()),
        table: "sc_cat_item".to_string(),
        sys_id: Some(detail.sys_id.clone()),
        diffs,
        commit_command: Some(cmd_parts.join(" ")),
        ..Default::default()
    };
    if let Some(res) = gate.first_record() {
        report.ticket = extract_field_display(res, "request_number")
            .or_else(|| extract_field_display(res, "number"));
        report.table = "sc_request".to_string();
        report.sys_id =
            extract_field_value(res, "request_id").or_else(|| extract_field_value(res, "sys_id"));
    }
    gate.fill(&mut report);
    Ok(report)
}

pub fn format_approvals(env: &ApprovalsEnvelope, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(env).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(env).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = format!("# Approvals ({} records)\n\n", env.count);
            out.push_str("| Approval sys_id | Target Ticket | Approver | State | Updated |\n");
            out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
            for item in &env.items {
                out.push_str(&format!(
                    "| `{}` | `{}` | {} | `{}` | {} |\n",
                    item.sys_id, item.target_ticket, item.approver, item.state, item.updated_on
                ));
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            if env.items.is_empty() {
                return "No matching approval records found.".to_string();
            }
            let mut table = Table::new();
            let width = table.width().unwrap_or(120).max(120);
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width)
                .set_header(vec![
                    "APPROVAL_SYS_ID",
                    "TARGET_TICKET",
                    "APPROVER",
                    "STATE",
                    "UPDATED_ON",
                ]);
            for item in &env.items {
                table.add_row(vec![
                    Cell::new(&item.sys_id),
                    Cell::new(&item.target_ticket),
                    Cell::new(&item.approver),
                    styled_table_cell("state", &item.state),
                    Cell::new(&item.updated_on),
                ]);
            }
            table.to_string()
        }
    }
}

pub fn format_catalog_search(items: &[CatalogItemSummary], format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(items).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(items).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = format!("# Service Catalog Items ({})\n\n", items.len());
            for item in items {
                out.push_str(&format!(
                    "- **{}** (`sys_id={}`): {}\n",
                    item.name, item.sys_id, item.short_description
                ));
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            if items.is_empty() {
                return "No matching Service Catalog items found.".to_string();
            }
            let mut table = Table::new();
            let width = table.width().unwrap_or(120).max(120);
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width)
                .set_header(vec!["SYS_ID", "NAME", "CATEGORY", "SHORT_DESCRIPTION"]);
            for item in items {
                table.add_row(vec![
                    item.sys_id.as_str(),
                    item.name.as_str(),
                    item.category.as_deref().unwrap_or(""),
                    item.short_description.as_str(),
                ]);
            }
            table.to_string()
        }
    }
}

pub fn format_catalog_detail(detail: &CatalogItemDetail, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(detail).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(detail).unwrap_or_default(),
        _ => {
            let mut out = format!(
                "# {} (`sys_id={}`)\n\n{}\n\n## Variables\n\n",
                detail.name, detail.sys_id, detail.short_description
            );
            for v in &detail.variables {
                out.push_str(&format!(
                    "- **`{}`** ({}, type: `{}`, mandatory: `{}`){}\n",
                    v.name,
                    v.label,
                    v.field_type,
                    v.mandatory,
                    if v.choices.is_empty() {
                        String::new()
                    } else {
                        format!(" — choices: {}", v.choices.join(", "))
                    }
                ));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use clap::Parser;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn lists_approvals_and_validates_catalog_order_dry_run() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sysapproval_approver"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "0123456789abcdef0123456789abcdef", "display_value": "0123456789abcdef0123456789abcdef" },
                    "state": { "value": "requested", "display_value": "Requested" },
                    "approver": { "value": "u1", "display_value": "Eric Sabe" },
                    "sysapproval": { "value": "chg1", "display_value": "CHG0031002" },
                    "sys_created_on": { "value": "2026-10-22 10:00:00", "display_value": "2026-10-22 10:00:00" },
                    "sys_updated_on": { "value": "2026-10-22 10:00:00", "display_value": "2026-10-22 10:00:00" }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/api/sn_sc/servicecatalog/items/fedcba9876543210fedcba9876543210",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": {
                    "sys_id": "fedcba9876543210fedcba9876543210",
                    "name": "AWS Sandbox Account",
                    "short_description": "Request a temporary AWS account",
                    "variables": [
                        {
                            "name": "aws_region",
                            "label": "AWS Region",
                            "type": "choice",
                            "mandatory": true,
                            "choices": [
                                { "label": "US East", "value": "us-east-1" }
                            ]
                        }
                    ]
                }
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

        let approvals = execute_approvals_list(
            &client,
            &cache,
            &ApprovalListArgs {
                state: "requested".to_string(),
                all_users: true,
            },
        )
        .await
        .expect("list approvals");
        assert_eq!(approvals.count, 1);
        assert_eq!(approvals.items[0].target_ticket, "CHG0031002");

        // Missing mandatory catalog variable fails validation (exit code 2)
        let missing_var_order = CatalogOrderArgs {
            item_sys_id: "fedcba9876543210fedcba9876543210".to_string(),
            variables: vec![],
            quantity: 1,
            requested_for: None,
            write: false,
        };
        let err = execute_catalog_order(client.clone(), &cache, &missing_var_order, None)
            .await
            .unwrap_err();
        assert_eq!(err.code().exit_code(), 2);

        // Passing mandatory variable succeeds in dry-run mode
        let valid_order = CatalogOrderArgs {
            item_sys_id: "fedcba9876543210fedcba9876543210".to_string(),
            variables: vec!["aws_region=us-east-1".to_string()],
            quantity: 1,
            requested_for: None,
            write: false,
        };
        let dry_run = execute_catalog_order(client, &cache, &valid_order, None)
            .await
            .expect("catalog order dry-run");
        assert_eq!(dry_run.mode, "dry_run");
        assert_eq!(dry_run.diffs.len(), 1);
        assert_eq!(
            dry_run.commit_command.as_deref(),
            Some(
                "sncfr catalog order fedcba9876543210fedcba9876543210 --var aws_region=us-east-1 --write"
            )
        );
    }

    const TICKET_SYS_ID: &str = "c0ffee00c0ffee00c0ffee00c0ffee00";
    const ME: &str = "11111111111111111111111111111111";
    const OTHER: &str = "22222222222222222222222222222222";
    const MY_GROUP: &str = "33333333333333333333333333333333";

    fn approval_row(
        sys_id: &str,
        state: &str,
        approver: (&str, &str),
        group: Option<(&str, &str)>,
    ) -> Value {
        let mut row = json!({
            "sys_id": { "value": sys_id, "display_value": sys_id },
            "state": { "value": state, "display_value": state[..1].to_uppercase() + &state[1..] },
            "approver": { "value": approver.0, "display_value": approver.1 },
            "sysapproval": { "value": TICKET_SYS_ID, "display_value": "CHG0031002" },
            "sys_created_on": { "value": "2026-10-22 10:00:00", "display_value": "2026-10-22 10:00:00" },
            "sys_updated_on": { "value": "2026-10-22 10:00:00", "display_value": "2026-10-22 10:00:00" }
        });
        if let Some((name, assignment_group)) = group {
            row["group"] = json!({ "value": "ag1", "display_value": name });
            row["group.assignment_group"] =
                json!({ "value": assignment_group, "display_value": name });
        }
        row
    }

    /// Mounts the approvals for one ticket plus a PATCH endpoint that must never be called,
    /// and returns a client whose identity cache holds `ME` in `MY_GROUP`.
    async fn approval_fixture(
        server: &MockServer,
        rows: Vec<Value>,
    ) -> (ReadOnlyClient, tempfile::TempDir, InstanceCache) {
        Mock::given(method("GET"))
            .and(path("/api/now/table/sysapproval_approver"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": rows })))
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": {} })))
            .expect(0)
            .mount(server)
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
        cache
            .write_identity(&CachedIdentity {
                sys_id: ME.to_string(),
                user_name: "pat.example".to_string(),
                display_name: "Pat Example".to_string(),
                email: None,
                groups: vec![crate::cache::CachedGroup {
                    sys_id: MY_GROUP.to_string(),
                    name: "Network - L2".to_string(),
                }],
            })
            .expect("write identity");
        (client, dir, cache)
    }

    fn approve_args(target: &str, write: bool) -> (ApprovalActionArgs, Option<WritePermit>) {
        let args = ApprovalActionArgs {
            approval_or_ticket: target.to_string(),
            comments: None,
            write,
        };
        let permit = write.then(|| {
            let cli = crate::cli::Cli::try_parse_from([
                "sncfr",
                "approvals",
                "approve",
                target,
                "--write",
            ])
            .expect("parse");
            WritePermit::issue(&cli, None)
                .expect("no lock")
                .expect("write permit issued")
        });
        (args, permit)
    }

    #[tokio::test]
    async fn approve_never_targets_another_users_or_non_pending_approval() {
        // CT-60: my approval is already rejected; the only pending one belongs to someone else.
        let server = MockServer::start().await;
        let rows = vec![
            approval_row(
                "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                "rejected",
                (ME, "Pat Example"),
                None,
            ),
            approval_row(
                "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
                "requested",
                (OTHER, "Sam Sample"),
                None,
            ),
        ];
        let (client, _dir, cache) = approval_fixture(&server, rows).await;

        let (args, permit) = approve_args(TICKET_SYS_ID, true);
        let err = execute_approval_action(client, &cache, &args, true, permit)
            .await
            .unwrap_err();
        assert_eq!(err.code().exit_code(), 5);
        let message = err.to_string();
        assert!(
            message.contains("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"),
            "{message}"
        );
        assert!(
            message.contains("a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn approve_with_several_of_my_pending_approvals_is_ambiguous() {
        // CT-61: two pending approvals are mine, one directly and one through my group.
        let server = MockServer::start().await;
        let rows = vec![
            approval_row(
                "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
                "requested",
                (ME, "Pat Example"),
                None,
            ),
            approval_row(
                "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
                "requested",
                (OTHER, "Sam Sample"),
                Some(("Network - L2", MY_GROUP)),
            ),
        ];
        let (client, _dir, cache) = approval_fixture(&server, rows).await;

        let (args, permit) = approve_args(TICKET_SYS_ID, true);
        let err = execute_approval_action(client, &cache, &args, true, permit)
            .await
            .unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        let SncfrError::Validation { valid_choices, .. } = &err else {
            panic!("expected validation error, got {err:?}");
        };
        assert_eq!(valid_choices.len(), 2);
        assert!(
            valid_choices
                .iter()
                .any(|c| c.contains("via group Network - L2"))
        );
    }

    #[tokio::test]
    async fn approve_targets_my_single_group_linked_pending_approval() {
        let server = MockServer::start().await;
        let rows = vec![
            approval_row(
                "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
                "requested",
                (OTHER, "Sam Sample"),
                None,
            ),
            approval_row(
                "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
                "requested",
                (OTHER, "Sam Sample"),
                Some(("Network - L2", MY_GROUP)),
            ),
        ];
        let (client, _dir, cache) = approval_fixture(&server, rows).await;

        let (args, _) = approve_args(TICKET_SYS_ID, false);
        let report = execute_approval_action(client, &cache, &args, true, None)
            .await
            .expect("dry-run");
        assert_eq!(report.mode, "dry_run");
        assert_eq!(
            report.sys_id.as_deref(),
            Some("a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6")
        );
    }

    #[tokio::test]
    async fn approve_by_approval_sys_id_still_requires_my_pending_approval() {
        let server = MockServer::start().await;
        let rows = vec![
            approval_row(
                "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
                "requested",
                (OTHER, "Sam Sample"),
                None,
            ),
            approval_row(
                "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
                "requested",
                (ME, "Pat Example"),
                None,
            ),
        ];
        let (client, _dir, cache) = approval_fixture(&server, rows).await;

        // Another user's approval named directly is refused even though one of mine exists.
        let (args, _) = approve_args("a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7", false);
        let err = execute_approval_action(client.clone(), &cache, &args, true, None)
            .await
            .unwrap_err();
        assert_eq!(err.code().exit_code(), 5);

        // Naming my own approval selects exactly that record.
        let (args, _) = approve_args("a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8", false);
        let report = execute_approval_action(client, &cache, &args, false, None)
            .await
            .expect("dry-run");
        assert_eq!(
            report.sys_id.as_deref(),
            Some("a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8")
        );
    }
}
