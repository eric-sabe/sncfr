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
    Binding, FieldDiff, FollowUpBlock, MutationReport, OrderedItem, parse_key_value_pair,
    resolve_user_reference, run_gate_staged, shell_quote,
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
        // `type` may be the numeric code or a friendly name.
        let by_name = match field_type.as_str() {
            "choice"
            | "select_box"
            | "multiple_choice"
            | "lookup_select_box"
            | "lookup_multiple_choice" => Some(VariableKind::Choice(Vec::new())),
            "reference" => Some(VariableKind::Reference {
                table: None,
                list: false,
            }),
            "list_collector" => Some(VariableKind::Reference {
                table: None,
                list: true,
            }),
            _ => None,
        };
        let kind = if !pairs.is_empty() {
            VariableKind::Choice(pairs.clone())
        } else {
            match by_name.unwrap_or_else(|| variable_type(&numeric).1) {
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

/// Resolves one `--var name=value` (CAT-4): choice sets are complete (non-match is exit 2),
/// references resolve like `--assign-to` / `--group`, free text is sent as typed, an unknown
/// name is `unknown_field`, and unreadable metadata is `no_metadata`.
async fn resolve_variable(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    detail: &CatalogItemDetail,
    name: &str,
    input: &str,
) -> Result<ResolvedValue, SncfrError> {
    use crate::resolve_value::{UnverifiableReason, unverifiable_catalog_value};
    if !detail.variables_readable {
        return Ok(unverifiable_catalog_value(
            input,
            UnverifiableReason::NoMetadata,
        ));
    }
    let Some(spec) = detail.variables.iter().find(|v| v.name == name) else {
        return Ok(unverifiable_catalog_value(
            input,
            UnverifiableReason::UnknownField,
        ));
    };
    match &spec.kind {
        VariableKind::FreeText => Ok(ResolvedValue::text(input)),
        VariableKind::Choice(pairs) => {
            crate::resolve_value::resolve_catalog_choice(name, input, pairs)
        }
        VariableKind::Reference { table, list } => {
            let Some(table) = table
                .as_deref()
                .filter(|t| crate::untrusted::is_table_name(t))
            else {
                return Ok(unverifiable_catalog_value(
                    input,
                    UnverifiableReason::NoMetadata,
                ));
            };
            let parts: Vec<&str> = if *list {
                input
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .collect()
            } else {
                vec![input.trim()]
            };
            let mut ids = Vec::new();
            let mut labels = Vec::new();
            for part in parts {
                match resolve_reference_value(client, cache, table, part).await? {
                    Some((id, label)) => {
                        ids.push(id);
                        labels.push(label);
                    }
                    None => {
                        return Ok(unverifiable_catalog_value(
                            input,
                            UnverifiableReason::NoMetadata,
                        ));
                    }
                }
            }
            Ok(ResolvedValue::verified(
                ids.join(","),
                Some(labels.join(", ")),
                None,
            ))
        }
    }
}

/// One reference value: a sys_id as given, users and groups through [`crate::references`]
/// (never guessing), other tables by exact `name`. `None` when it cannot be confirmed.
async fn resolve_reference_value(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    table: &str,
    input: &str,
) -> Result<Option<(String, String)>, SncfrError> {
    if is_sys_id(input) {
        return Ok(Some((input.to_string(), input.to_string())));
    }
    match table {
        "sys_user" => {
            let m = crate::references::resolve_user(client, cache, input).await?;
            Ok(Some((m.sys_id, m.name)))
        }
        "sys_user_group" => {
            let m = crate::references::resolve_group(client, cache, input).await?;
            Ok(Some((m.sys_id, m.name)))
        }
        _ => {
            let q = format!("name={}", crate::untrusted::query_value(input)?);
            let Ok(resp) = client
                .get_json::<Value>(
                    &format!("/api/now/table/{table}"),
                    &[
                        ("sysparm_query", q.as_str()),
                        ("sysparm_fields", "sys_id,name"),
                        ("sysparm_limit", "2"),
                    ],
                )
                .await
            else {
                return Ok(None);
            };
            let rows = resp
                .get("result")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            match rows.as_slice() {
                [one] => Ok(extract_field_value(one, "sys_id")
                    .map(|id| (id, extract_field_display(one, "name").unwrap_or_default()))),
                [] => Ok(None),
                _ => Err(SncfrError::AmbiguousReference {
                    kind: table.to_string(),
                    input: input.to_string(),
                    detail: format!("more than one {table} record is named exactly this"),
                    candidates: rows
                        .iter()
                        .filter_map(|r| extract_field_display(r, "name"))
                        .collect(),
                    suggestion: None,
                }),
            }
        }
    }
}

/// How long to wait for an order's requested items (CAT-2): backoff from `initial`, doubling,
/// capped at `cap` per wait and `max_wait` in total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollPolicy {
    pub initial: std::time::Duration,
    pub cap: std::time::Duration,
    pub max_wait: std::time::Duration,
}

impl PollPolicy {
    /// `--poll-timeout`, else pack `catalog.poll.max_wait_secs`, else 20 s; backoff from pack
    /// `initial_backoff_ms`, else 500 ms.
    pub fn resolve(pack: &crate::pack::MergedPack, poll_timeout: Option<u64>) -> Self {
        let poll = pack.catalog.poll.clone().unwrap_or_default();
        let max = poll_timeout.unwrap_or_else(|| u64::from(poll.max_wait_secs.unwrap_or(20)));
        Self {
            initial: std::time::Duration::from_millis(u64::from(
                poll.initial_backoff_ms.unwrap_or(500),
            )),
            cap: std::time::Duration::from_secs(4),
            max_wait: std::time::Duration::from_secs(max),
        }
    }
}

/// Polls `sc_req_item?request=<req>` until it returns rows or the policy's total wait is spent.
/// A timeout or an unreadable table is a warning, never an error (CAT-2).
pub async fn poll_requested_items(
    client: &ReadOnlyClient,
    request_sys_id: &str,
    policy: PollPolicy,
) -> (Vec<OrderedItem>, Option<String>) {
    if !is_sys_id(request_sys_id) {
        return (
            Vec::new(),
            Some(
                "The order response carried no request sys_id; requested items were not polled."
                    .to_string(),
            ),
        );
    }
    let q = format!("request={request_sys_id}");
    let mut waited = std::time::Duration::ZERO;
    let mut wait = policy.initial;
    loop {
        if waited + wait > policy.max_wait {
            return (
                Vec::new(),
                Some(format!(
                    "No requested item appeared within {}s; check the request later with `sncfr list --table sc_req_item`.",
                    policy.max_wait.as_secs()
                )),
            );
        }
        tokio::time::sleep(wait).await;
        waited += wait;
        wait = (wait * 2).min(policy.cap);
        match client
            .get_json::<Value>(
                "/api/now/table/sc_req_item",
                &[
                    ("sysparm_query", q.as_str()),
                    ("sysparm_fields", "sys_id,number,cat_item"),
                    ("sysparm_limit", "50"),
                ],
            )
            .await
        {
            Ok(resp) => {
                let items: Vec<OrderedItem> = resp
                    .get("result")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|r| {
                        Some(OrderedItem {
                            sys_id: extract_field_value(r, "sys_id")?,
                            number: extract_field_display(r, "number").unwrap_or_default(),
                            cat_item: extract_field_value(r, "cat_item").unwrap_or_default(),
                        })
                    })
                    .collect();
                if !items.is_empty() {
                    return (items, None);
                }
            }
            Err(e) => {
                return (
                    Vec::new(),
                    Some(format!(
                        "Requested items could not be read ({}).",
                        e.code().as_str()
                    )),
                );
            }
        }
    }
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

    // CAT-4: every `--var` goes through the SAFE chain against the item's metadata.
    for kv in &args.variables {
        let (k, v) = parse_key_value_pair(kv)?;
        let value = resolve_variable(&client, cache, &detail, &k, &v).await?;
        diffs.push(FieldDiff::from_resolved(
            &format!("var:{k}"),
            None,
            &v,
            &value,
        ));
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
    // CAT-3: the post-order fill, checked with the order before anything is sent.
    let fill = if args.fill_ritm {
        Some(plan_fill(&client, cache, &variables).await?)
    } else {
        None
    };
    if fill.is_some() {
        cmd_parts.insert(cmd_parts.len() - 1, "--fill-ritm".to_string());
    }
    let mut mutations = vec![mutation];
    if let Some((_, fill_fields)) = &fill {
        mutations.push(VerifiedMutation::record(
            Target::deferred_patch("sc_req_item")?,
            fill_fields,
        ));
    }

    let reader = client.clone();
    let policy = PollPolicy::resolve(crate::pack::active(), args.poll_timeout);
    let item_sys_id = detail.sys_id.clone();
    let fill_cmd_set: Vec<String> = fill
        .iter()
        .flat_map(|(_, f)| {
            f.iter()
                .map(|(k, _, v)| format!("--set {}", shell_quote(&format!("{k}={}", v.value()))))
        })
        .collect();
    let wants_fill = fill.is_some();
    let gate = run_gate_staged(client, permit, mutations, |first| {
        let req = first
            .map(|o| o.response.get("result").unwrap_or(&o.response))
            .and_then(|r| {
                extract_field_value(r, "request_id").or_else(|| extract_field_value(r, "sys_id"))
            })
            .unwrap_or_default();
        async move {
            // CAT-2: wait for the requested items.
            let (items, warning) = poll_requested_items(&reader, &req, policy).await;
            let mut binding = Binding {
                sys_id: None,
                warnings: warning.into_iter().collect(),
                items,
            };
            if wants_fill {
                bind_fill(&mut binding, &item_sys_id, &fill_cmd_set);
            }
            binding
        }
    })
    .await?;
    let mut report = MutationReport {
        operation: "catalog_order".to_string(),
        ticket: Some(detail.name.clone()),
        table: "sc_cat_item".to_string(),
        sys_id: Some(detail.sys_id.clone()),
        diffs,
        commit_command: Some(cmd_parts.join(" ")),
        fill_ritm: fill.map(|(diffs, _)| FollowUpBlock {
            target: RITM_PLACEHOLDER.to_string(),
            diffs,
        }),
        ..Default::default()
    };
    if let Some(res) = gate.first_record() {
        report.ticket = extract_field_display(res, "request_number")
            .or_else(|| extract_field_display(res, "number"));
        report.table = "sc_request".to_string();
        report.sys_id =
            extract_field_value(res, "request_id").or_else(|| extract_field_value(res, "sys_id"));
    }
    let bound = gate.binding.as_ref().and_then(|b| {
        let id = b.sys_id.as_ref()?;
        b.items.iter().find(|i| &i.sys_id == id)
    });
    if let (Some(block), Some(item)) = (report.fill_ritm.as_mut(), bound) {
        block.target.clone_from(&item.number);
    }
    gate.fill(&mut report);
    Ok(report)
}

/// The fill's target before the order runs.
const RITM_PLACEHOLDER: &str = "<RITM created by this order>";

/// CAT-3: the pack's `catalog.post_order_fill.fields`, with `{var.<name>}` replaced by the
/// order's resolved variable values, each resolved for `sc_req_item` through the SAFE chain.
async fn plan_fill(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    variables: &[ResolvedField],
) -> Result<(Vec<FieldDiff>, Vec<ResolvedField>), SncfrError> {
    let pack = crate::pack::active();
    let templates = pack
        .catalog
        .post_order_fill
        .as_ref()
        .map(|f| f.fields.clone())
        .unwrap_or_default();
    if templates.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "--fill-ritm needs `catalog.post_order_fill.fields` in the Instance Pack"
                .to_string(),
            remediation: Some("Add the fields to the pack, or drop --fill-ritm.".to_string()),
        });
    }
    let schema =
        crate::schema::load_or_sync_table_schema(client, cache, "sc_req_item", false).await?;
    let ctx = crate::resolve_value::ResolveCtx {
        pack,
        table: "sc_req_item",
        schema: &schema,
        sample: None,
        discovered: None,
    };
    let mut diffs = Vec::new();
    let mut fields: Vec<ResolvedField> = Vec::new();
    for (field, template) in &templates {
        let value = render_fill_template(template, variables)?;
        let resolved = crate::resolve_value::resolve_field(&ctx, field, &value)?;
        diffs.push(FieldDiff::from_resolved(field, None, &value, &resolved));
        fields.push((field.clone(), value, resolved));
    }
    Ok((diffs, fields))
}

/// `"{var.cost_center}"` → the order's resolved `cost_center` value. A placeholder naming a
/// variable the order does not set is exit 2.
fn render_fill_template(template: &str, variables: &[ResolvedField]) -> Result<String, SncfrError> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{var.") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let name = &after[..end];
        let Some((_, _, v)) = variables.iter().find(|(n, _, _)| n == name) else {
            return Err(SncfrError::InvalidArgs {
                message: format!(
                    "the post-order fill uses `{{var.{name}}}`, but the order sets no `{name}`"
                ),
                remediation: Some(format!("Pass `--var {name}=<value>`, or drop --fill-ritm.")),
            });
        };
        out.push_str(v.value());
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Picks the one RITM the fill may write (`cat_item` = the ordered item). RITMs of other items
/// are skipped with a warning; none or several leave the fill unsent, with the exact command.
fn bind_fill(binding: &mut Binding, item_sys_id: &str, set_args: &[String]) {
    let (mine, others): (Vec<&OrderedItem>, Vec<&OrderedItem>) = binding
        .items
        .iter()
        .partition(|i| i.cat_item == item_sys_id);
    let mut warnings: Vec<String> = others
        .iter()
        .map(|o| {
            format!(
                "{} is for another catalog item; the fill skipped it.",
                o.number
            )
        })
        .collect();
    let command = |ritm: &str| format!("sncfr update {ritm} {} --write", set_args.join(" "));
    match mine.as_slice() {
        [one] => binding.sys_id = Some(one.sys_id.clone()),
        [] => warnings.push(format!(
            "The fill was not sent: no requested item for this order appeared. When it does, run: {}",
            command("<RITM>")
        )),
        many => {
            for m in many {
                warnings.push(format!(
                    "The fill was not sent: this order created several requested items. For {}, run: {}",
                    m.number,
                    command(&m.number)
                ));
            }
        }
    }
    binding.warnings.extend(warnings);
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
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ITEM: &str = "fedcba9876543210fedcba9876543211";

    fn order(vars: &[&str]) -> CatalogOrderArgs {
        CatalogOrderArgs {
            item_sys_id: ITEM.to_string(),
            variables: vars.iter().map(|v| (*v).to_string()).collect(),
            quantity: 1,
            requested_for: None,
            write: false,
            poll_timeout: None,
            fill_ritm: false,
        }
    }

    #[tokio::test]
    async fn catalog_variables_go_through_the_safe_chain() {
        // CT-62b (CAT-4)
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/sn_sc/servicecatalog/items/{ITEM}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": {
                    "sys_id": ITEM,
                    "name": "Example Laptop",
                    "variables": [
                        { "name": "model", "label": "Model", "type": "choice", "mandatory": true,
                          "choices": [ { "label": "Standard", "value": "standard" },
                                       { "label": "Power user", "value": "power" } ] },
                        { "name": "notes", "label": "Notes", "type": "string" }
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

        let bad = execute_catalog_order(client.clone(), &cache, &order(&["model=gold"]), None)
            .await
            .unwrap_err();
        assert_eq!(bad.code().exit_code(), 2, "not in the choice set");

        let unknown = execute_catalog_order(
            client.clone(),
            &cache,
            &order(&["model=standard", "colour=red"]),
            None,
        )
        .await
        .expect("dry-run");
        assert_eq!(unknown.unverifiable_fields.len(), 1);
        assert_eq!(unknown.unverifiable_fields[0].field, "var:colour");
        assert_eq!(unknown.unverifiable_fields[0].reason, "unknown_field");

        let ok = execute_catalog_order(
            client,
            &cache,
            &order(&["model=Power user", "notes=anything goes"]),
            None,
        )
        .await
        .expect("dry-run");
        assert!(ok.unverifiable_fields.is_empty());
        let model = ok
            .diffs
            .iter()
            .find(|d| d.field == "var:model")
            .expect("model");
        assert_eq!(model.after_value, "power");
        assert_eq!(model.source.as_deref(), Some("sys_choice"));
    }

    #[tokio::test]
    async fn requested_items_are_polled_with_backoff_and_a_timeout_only_warns() {
        // CT-39 (CAT-2)
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct ThirdPoll(AtomicUsize);
        impl wiremock::Respond for ThirdPoll {
            fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
                let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                let rows = if n >= 3 {
                    json!([{ "sys_id": "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1", "number": "RITM0050001", "cat_item": ITEM }])
                } else {
                    json!([])
                };
                ResponseTemplate::new(200).set_body_json(json!({ "result": rows }))
            }
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/sc_req_item"))
            .respond_with(ThirdPoll(AtomicUsize::new(0)))
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
        let fast = PollPolicy {
            initial: std::time::Duration::from_millis(5),
            cap: std::time::Duration::from_millis(20),
            max_wait: std::time::Duration::from_millis(500),
        };
        let req = "abababababababababababababababab";
        let (items, warning) = poll_requested_items(&client, req, fast).await;
        assert_eq!(warning, None);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].number, "RITM0050001");
        let polls = server.received_requests().await.unwrap_or_default().len();
        assert_eq!(polls, 3, "appears on the 3rd poll");

        let none = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/sc_req_item"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&none)
            .await;
        let client = ReadOnlyClient::new(
            Url::parse(&none.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let tiny = PollPolicy {
            max_wait: std::time::Duration::from_millis(40),
            ..fast
        };
        let (items, warning) = poll_requested_items(&client, req, tiny).await;
        assert!(items.is_empty());
        assert!(
            warning
                .expect("warning")
                .contains("No requested item appeared")
        );

        let pack = crate::pack::ootb_merged();
        let p = PollPolicy::resolve(&pack, None);
        assert_eq!(
            (p.initial.as_millis(), p.cap.as_secs(), p.max_wait.as_secs()),
            (500, 4, 20)
        );
        assert_eq!(PollPolicy::resolve(&pack, Some(5)).max_wait.as_secs(), 5);
    }

    /// A catalog item, an order_now that answers with REQ0000001, and one RITM for the item.
    async fn order_server(with_order: bool) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/sn_sc/servicecatalog/items/{ITEM}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": { "sys_id": ITEM, "name": "Example Laptop",
                    "variables": [ { "name": "cost_center", "label": "Cost center", "type": "string" } ] }
            })))
            .mount(&server)
            .await;
        for t in ["sys_number", "sys_dictionary", "sys_choice"] {
            Mock::given(method("GET"))
                .and(path(format!("/api/now/table/{t}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
                .mount(&server)
                .await;
        }
        if with_order {
            Mock::given(method("POST"))
                .and(path(format!("/api/sn_sc/servicecatalog/items/{ITEM}/order_now")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": { "request_number": "REQ0000001", "request_id": "abababababababababababababababab" }
                })))
                .mount(&server)
                .await;
        }
        server
    }

    #[tokio::test]
    async fn fill_ritm_previews_a_second_block_and_blocks_the_order_when_unverifiable() {
        // CT-40, CT-40b (CAT-3; NA-2): with the ootb pack there is no fill config, so the pack
        // is exercised through `plan_fill`'s pure parts and the gate through a blocked fill.
        let vars: Vec<ResolvedField> = vec![(
            "cost_center".to_string(),
            "CC-900".to_string(),
            ResolvedValue::text("CC-900"),
        )];
        assert_eq!(
            render_fill_template("{var.cost_center}", &vars).unwrap(),
            "CC-900"
        );
        assert_eq!(
            render_fill_template("cc:{var.cost_center}!", &vars).unwrap(),
            "cc:CC-900!"
        );
        assert_eq!(
            render_fill_template("{var.nope}", &vars)
                .unwrap_err()
                .code()
                .exit_code(),
            2
        );

        let mut binding = Binding {
            items: vec![
                OrderedItem {
                    sys_id: "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1".into(),
                    number: "RITM1".into(),
                    cat_item: ITEM.into(),
                },
                OrderedItem {
                    sys_id: "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2".into(),
                    number: "RITM2".into(),
                    cat_item: "other".into(),
                },
            ],
            ..Default::default()
        };
        bind_fill(
            &mut binding,
            ITEM,
            &["--set 'u_cost_center=CC-900'".to_string()],
        );
        assert_eq!(
            binding.sys_id.as_deref(),
            Some("e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1")
        );
        assert!(binding.warnings[0].contains("RITM2 is for another catalog item"));
        let mut none = Binding::default();
        bind_fill(
            &mut none,
            ITEM,
            &["--set 'u_cost_center=CC-900'".to_string()],
        );
        assert_eq!(none.sys_id, None);
        assert!(
            none.warnings[0].contains("sncfr update <RITM> --set 'u_cost_center=CC-900' --write")
        );

        // The gate: an unverifiable deferred fill blocks the order itself (zero POST).
        let server = order_server(true).await;
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
        let schema =
            crate::schema::load_or_sync_table_schema(&client, &cache, "sc_req_item", false)
                .await
                .expect("schema");
        let pack = crate::pack::ootb_merged();
        let ctx = crate::resolve_value::ResolveCtx {
            pack: &pack,
            table: "sc_req_item",
            schema: &schema,
            sample: None,
            discovered: None,
        };
        let fill_value =
            crate::resolve_value::resolve_field(&ctx, "u_cost_center", "CC-900").unwrap();
        assert!(
            fill_value.unverifiable().is_some(),
            "unknown field on a dictionary-less instance"
        );
        let order =
            VerifiedMutation::catalog_order(Target::catalog_order(ITEM).unwrap(), json!({}), &vars);
        let fill = VerifiedMutation::record(
            Target::deferred_patch("sc_req_item").unwrap(),
            &[(
                "u_cost_center".to_string(),
                "CC-900".to_string(),
                fill_value,
            )],
        );
        let permit = crate::client::WritePermit::issue(
            &<crate::cli::Cli as clap::Parser>::parse_from([
                "sncfr",
                "--instance",
                "x",
                "catalog",
                "order",
                ITEM,
                "--write",
            ]),
            None,
        )
        .expect("permit")
        .expect("write");
        let gate = crate::mutate::run_gate_staged(
            client.clone(),
            Some(permit),
            vec![order, fill],
            |_| async { Binding::default() },
        )
        .await
        .expect("gate");
        assert_eq!(gate.mode, "blocked");
        assert_eq!(gate.blocking[0].field, "u_cost_center");
        let posts = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() != "GET")
            .count();
        assert_eq!(posts, 0, "zero POST to order_now");

        // Dry-run preview: the second block appears and nothing is written.
        let report = MutationReport {
            fill_ritm: Some(FollowUpBlock {
                target: RITM_PLACEHOLDER.to_string(),
                diffs: vec![FieldDiff::from_resolved(
                    "u_cost_center",
                    None,
                    "CC-900",
                    &ResolvedValue::text("CC-900"),
                )],
            }),
            ..Default::default()
        };
        let text = crate::mutate::format_mutation_report(&report, ResolvedOutputFormat::Md);
        assert!(
            text.contains("Then on <RITM created by this order>"),
            "{text}"
        );
    }
}
