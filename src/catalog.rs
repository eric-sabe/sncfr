//! Service Catalog: `catalog search | show | order` (CAT-1..4).
//!
//! Reads use the `sn_sc` API when the capability record allows it, and fall back to the Table
//! API (`sc_cat_item`, `item_option_new`, `question_choice`) when the API is unauthorized or
//! unavailable. Ordering has no fallback.

use crate::cache::InstanceCache;
use crate::cli::CatalogOrderArgs;
use crate::client::write_gate::{ResolvedField, Target, VerifiedMutation};
use crate::client::{ReadOnlyClient, WritePermit, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::mutate::{
    FieldDiff, MutationReport, parse_key_value_pair, resolve_user_reference, run_gate, shell_quote,
};
use crate::output::ResolvedOutputFormat;
use crate::resolve::is_sys_id;
use crate::resolve_value::ResolvedValue;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogItemSummary {
    pub sys_id: String,
    pub name: String,
    pub short_description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// `table_api_fallback` when read from `sc_cat_item` instead of the `sn_sc` API (CAT-1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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
    /// How `--var` values are checked (CAT-4).
    #[serde(skip)]
    pub kind: VariableKind,
}

/// What a catalog variable accepts, for `--var` validation (CAT-4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VariableKind {
    /// Select box, multiple choice, lookup select: `(value, label)` pairs from `question_choice`
    /// or the `sn_sc` item. Empty when the choices could not be read.
    Choice(Vec<(String, String)>),
    /// Reference or list collector to a table (`None` when the table is unknown).
    Reference { table: Option<String>, list: bool },
    /// Text, numbers, dates, checkboxes: sent as typed.
    #[default]
    FreeText,
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
    /// `table_api_fallback` when read from the Table API instead of the `sn_sc` API (CAT-1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// False when the variable metadata could not be read at all (CAT-4 `no_metadata`).
    #[serde(skip)]
    pub variables_readable: bool,
}

/// Source label for reads served by the Table API instead of `sn_sc` (CAT-1).
pub const TABLE_API_FALLBACK: &str = "table_api_fallback";

/// Whether the `sn_sc` API is worth calling (capability `catalog_api` available or unknown).
fn catalog_api_usable(cache: &InstanceCache) -> bool {
    crate::capabilities::state(cache, crate::capabilities::Capability::CatalogApi).worth_trying()
}

/// An `sn_sc` failure that a read may answer from the Table API instead (CAP-4 401, 403, 404).
/// Records what was learned; CAP-4 records `ApiFamilyUnauthorized` itself.
fn api_falls_back(cache: &InstanceCache, err: &SncfrError) -> bool {
    use crate::capabilities::{CapHint, CapSource, CapState, Capability, CapabilityRecord};
    match err {
        SncfrError::ApiFamilyUnauthorized { .. } => true,
        SncfrError::AclForbidden { .. } => {
            CapabilityRecord::observe(
                cache,
                Capability::CatalogApi,
                CapState::Unauthorized,
                CapSource::Observed,
                Some(403),
                Some(CapHint::Acl),
            );
            true
        }
        SncfrError::NotFound { .. } => {
            CapabilityRecord::observe(
                cache,
                Capability::CatalogApi,
                CapState::Unavailable,
                CapSource::Observed,
                Some(404),
                None,
            );
            true
        }
        _ => false,
    }
}

fn summary_rows(resp: &Value, source: Option<&str>) -> Vec<CatalogItemSummary> {
    let mut items = Vec::new();
    for row in resp
        .get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
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
                source: source.map(str::to_string),
            });
        }
    }
    items
}

/// Executes `sncfr catalog search <query> [--limit <n>]`.
pub async fn execute_catalog_search(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    query: &str,
    limit: u32,
) -> Result<Vec<CatalogItemSummary>, SncfrError> {
    let limit_str = limit.to_string();
    if catalog_api_usable(cache) {
        match client
            .get_json::<Value>(
                "/api/sn_sc/servicecatalog/items",
                &[
                    ("sysparm_text", query),
                    ("sysparm_limit", limit_str.as_str()),
                ],
            )
            .await
        {
            Ok(resp) => return Ok(summary_rows(&resp, None)),
            Err(e) if api_falls_back(cache, &e) => {}
            Err(e) => return Err(e),
        }
    }

    // CAT-1: the Table API, annotated as a fallback. The text is a query value (NA-13).
    let text = crate::untrusted::query_value(query)?;
    let q = format!("active=true^nameLIKE{text}^ORshort_descriptionLIKE{text}");
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
    Ok(summary_rows(&resp, Some(TABLE_API_FALLBACK)))
}

/// `item_option_new.type` codes → (friendly name, how `--var` values are checked).
fn variable_type(code: &str) -> (String, VariableKind) {
    let choice = || VariableKind::Choice(Vec::new());
    let (name, kind) = match code {
        "1" => ("yes_no", VariableKind::FreeText),
        "2" => ("multi_line_text", VariableKind::FreeText),
        "3" => ("multiple_choice", choice()),
        "4" => ("numeric_scale", VariableKind::FreeText),
        "5" => ("select_box", choice()),
        "6" => ("single_line_text", VariableKind::FreeText),
        "7" => ("checkbox", VariableKind::FreeText),
        "8" => (
            "reference",
            VariableKind::Reference {
                table: None,
                list: false,
            },
        ),
        "9" => ("date", VariableKind::FreeText),
        "10" => ("date_time", VariableKind::FreeText),
        "18" => ("lookup_select_box", choice()),
        "21" => (
            "list_collector",
            VariableKind::Reference {
                table: None,
                list: true,
            },
        ),
        "22" => ("lookup_multiple_choice", choice()),
        "26" => ("email", VariableKind::FreeText),
        "31" => (
            "requested_for",
            VariableKind::Reference {
                table: Some("sys_user".to_string()),
                list: false,
            },
        ),
        other => return (format!("type_{other}"), VariableKind::FreeText),
    };
    (name.to_string(), kind)
}

/// The `sn_sc` item's `variables[]` (CAT-4 metadata when the API is available).
fn api_variables(res: &Value) -> Vec<CatalogVariableSpec> {
    let mut variables = Vec::new();
    for v in res
        .get("variables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
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
        let pairs: Vec<(String, String)> = v
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|ch| {
                let val = ch.get("value").and_then(Value::as_str).unwrap_or_default();
                let lbl = ch.get("label").and_then(Value::as_str).unwrap_or(val);
                (!val.is_empty()).then(|| (val.to_string(), lbl.to_string()))
            })
            .collect();
        let numeric = v
            .get("type")
            .and_then(|t| {
                t.as_u64()
                    .map(|n| n.to_string())
                    .or_else(|| t.as_str().map(str::to_string))
            })
            .unwrap_or_default();
        let kind = if !pairs.is_empty() {
            VariableKind::Choice(pairs.clone())
        } else {
            match variable_type(&numeric).1 {
                VariableKind::Reference { table, list } => VariableKind::Reference {
                    table: v
                        .get("reference")
                        .and_then(Value::as_str)
                        .filter(|t| !t.is_empty())
                        .map(str::to_string)
                        .or(table),
                    list,
                },
                VariableKind::Choice(_) => VariableKind::Choice(Vec::new()),
                VariableKind::FreeText => VariableKind::FreeText,
            }
        };
        variables.push(CatalogVariableSpec {
            name: var_name.to_string(),
            label,
            field_type,
            mandatory,
            default_value,
            choices: pairs.iter().map(|(v, l)| format!("{l} ({v})")).collect(),
            kind,
        });
    }
    variables
}

/// CAT-1 fallback for `show`: `sc_cat_item`, its active `item_option_new` rows (ordered
/// client-side by `order`), and their `question_choice` values.
async fn show_from_tables(
    client: &ReadOnlyClient,
    item_sys_id: &str,
) -> Result<CatalogItemDetail, SncfrError> {
    let item: Value = client
        .get_json(
            &format!("/api/now/table/sc_cat_item/{item_sys_id}"),
            &[
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "sys_id,name,short_description,description",
                ),
            ],
        )
        .await?;
    let res = item.get("result").unwrap_or(&item);
    let q = format!("cat_item={item_sys_id}^active=true");
    let (rows, readable) = match client
        .get_json::<Value>(
            "/api/now/table/item_option_new",
            &[
                ("sysparm_query", q.as_str()),
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "sys_id,name,question_text,type,mandatory,default_value,order,reference,list_table",
                ),
                ("sysparm_limit", "200"),
            ],
        )
        .await
    {
        Ok(v) => (
            v.get("result").and_then(Value::as_array).cloned().unwrap_or_default(),
            true,
        ),
        Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => {
            return Err(e);
        }
        Err(_) => (Vec::new(), false),
    };
    let mut rows = rows;
    rows.sort_by_key(|r| {
        extract_field_value(r, "order")
            .and_then(|o| o.parse::<i64>().ok())
            .unwrap_or(i64::MAX)
    });

    // Choices for choice-typed questions, in one request.
    let choice_ids: Vec<String> = rows
        .iter()
        .filter(|r| {
            matches!(
                variable_type(&extract_field_value(r, "type").unwrap_or_default()).1,
                VariableKind::Choice(_)
            )
        })
        .filter_map(|r| extract_field_value(r, "sys_id"))
        .filter(|id| is_sys_id(id))
        .collect();
    let mut choices: std::collections::BTreeMap<String, Vec<(String, String, i64)>> =
        std::collections::BTreeMap::new();
    if !choice_ids.is_empty() {
        let q = format!("questionIN{}^inactive=false", choice_ids.join(","));
        if let Ok(v) = client
            .get_json::<Value>(
                "/api/now/table/question_choice",
                &[
                    ("sysparm_query", q.as_str()),
                    ("sysparm_fields", "question,text,value,order"),
                    ("sysparm_limit", "1000"),
                ],
            )
            .await
        {
            for c in v
                .get("result")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let (Some(question), Some(value)) = (
                    extract_field_value(c, "question"),
                    extract_field_value(c, "value"),
                ) else {
                    continue;
                };
                let text = extract_field_display(c, "text").unwrap_or_else(|| value.clone());
                let order = extract_field_value(c, "order")
                    .and_then(|o| o.parse::<i64>().ok())
                    .unwrap_or(i64::MAX);
                choices
                    .entry(question)
                    .or_default()
                    .push((value, text, order));
            }
        }
    }

    let mut variables = Vec::new();
    for r in &rows {
        let Some(name) = extract_field_value(r, "name").filter(|n| !n.is_empty()) else {
            continue;
        };
        let (field_type, mut kind) =
            variable_type(&extract_field_value(r, "type").unwrap_or_default());
        match &mut kind {
            VariableKind::Choice(pairs) => {
                let id = extract_field_value(r, "sys_id").unwrap_or_default();
                let mut found = choices.remove(&id).unwrap_or_default();
                found.sort_by_key(|(_, _, o)| *o);
                *pairs = found.into_iter().map(|(v, t, _)| (v, t)).collect();
            }
            VariableKind::Reference { table, list } => {
                let field = if *list { "list_table" } else { "reference" };
                if let Some(t) = extract_field_value(r, field).filter(|t| !t.is_empty()) {
                    *table = Some(t);
                }
            }
            VariableKind::FreeText => {}
        }
        let pairs: Vec<String> = match &kind {
            VariableKind::Choice(p) => p.iter().map(|(v, l)| format!("{l} ({v})")).collect(),
            _ => Vec::new(),
        };
        variables.push(CatalogVariableSpec {
            label: extract_field_display(r, "question_text").unwrap_or_else(|| name.clone()),
            name,
            field_type,
            mandatory: extract_field_value(r, "mandatory")
                .is_some_and(|m| m.eq_ignore_ascii_case("true")),
            default_value: extract_field_value(r, "default_value").filter(|d| !d.is_empty()),
            choices: pairs,
            kind,
        });
    }
    Ok(CatalogItemDetail {
        sys_id: extract_field_value(res, "sys_id").unwrap_or_else(|| item_sys_id.to_string()),
        name: extract_field_display(res, "name").unwrap_or_else(|| item_sys_id.to_string()),
        short_description: extract_field_display(res, "short_description").unwrap_or_default(),
        description: extract_field_display(res, "description"),
        variables,
        source: Some(TABLE_API_FALLBACK.to_string()),
        variables_readable: readable,
    })
}

/// Executes `sncfr catalog show <item_sys_id_or_name>`.
pub async fn execute_catalog_show(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    item: &str,
) -> Result<CatalogItemDetail, SncfrError> {
    let trimmed = item.trim();
    let item_sys_id = if is_sys_id(trimmed) {
        trimmed.to_string()
    } else {
        let found = execute_catalog_search(client, cache, trimmed, 5).await?;
        found
            .into_iter()
            .find(|i| i.name.eq_ignore_ascii_case(trimmed))
            .map(|i| i.sys_id)
            .ok_or_else(|| SncfrError::NotFound {
                identifier: trimmed.to_string(),
                table: Some("sc_cat_item".to_string()),
            })?
    };

    if catalog_api_usable(cache) {
        let path = format!("/api/sn_sc/servicecatalog/items/{item_sys_id}");
        match client.get_json::<Value>(&path, &[]).await {
            Ok(resp) => {
                let res = resp.get("result").unwrap_or(&resp);
                return Ok(CatalogItemDetail {
                    name: extract_field_display(res, "name").unwrap_or_else(|| item_sys_id.clone()),
                    short_description: extract_field_display(res, "short_description")
                        .unwrap_or_default(),
                    description: extract_field_display(res, "description"),
                    variables: api_variables(res),
                    sys_id: item_sys_id,
                    source: None,
                    variables_readable: true,
                });
            }
            Err(e) if api_falls_back(cache, &e) => {}
            Err(e) => return Err(e),
        }
    }
    show_from_tables(client, &item_sys_id).await
}

/// Executes `sncfr catalog order <item_sys_id> [--var k=v...] [--write]`.
pub async fn execute_catalog_order(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &CatalogOrderArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    // CAT-1: ordering has no Table API fallback (NA-16).
    let refuse =
        |state: crate::capabilities::CapState, item: &str| SncfrError::CatalogOrderUnauthorized {
            state: state.as_str().to_string(),
            portal_url: format!(
                "{}/sp?id=sc_cat_item&sys_id={}",
                client.base_url().as_str().trim_end_matches('/'),
                crate::untrusted::inline(item)
            ),
        };
    let api_state = crate::capabilities::state(cache, crate::capabilities::Capability::CatalogApi);
    if !api_state.worth_trying() {
        return Err(refuse(api_state, &args.item_sys_id));
    }
    let detail = execute_catalog_show(&client, cache, &args.item_sys_id).await?;
    if detail.source.is_some() {
        let state = crate::capabilities::state(cache, crate::capabilities::Capability::CatalogApi);
        return Err(refuse(state, &detail.sys_id));
    }
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
