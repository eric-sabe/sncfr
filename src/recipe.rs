//! `sncfr recipe list | run` (WF-2, WF-3): pack-defined, read-only sequences of `table`,
//! `stats`, and `show` steps.
//!
//! The mutation guard is structural: [`RecipeStep`] is a closed enum with no method, body, or
//! write flag, and [`run`] only ever holds a `&ReadOnlyClient` (NA-1). Substitution happens only
//! in `query` and `Show.ticket`, and every substituted value passes the query-value guard
//! (NA-10, NA-13). A step that a later step depends on must yield exactly one row.

use crate::cache::InstanceCache;
use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::pack::schema::{RecipeFile, RecipeStep};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Rows a `table` step returns when it sets no `limit`.
const DEFAULT_LIMIT: u32 = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub params: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepOutput {
    pub id: String,
    /// `table`, `stats`, or `show`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub table: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub query: String,
    /// Display values per row (`table`, `show`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<BTreeMap<String, String>>,
    /// `(display value, value, count)` per group (`stats`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<crate::monitor::StatsBucket>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeOutput {
    pub recipe: String,
    pub params: BTreeMap<String, String>,
    pub steps: Vec<StepOutput>,
}

/// Every recipe in the merged pack.
pub fn list(pack: &crate::pack::MergedPack) -> Vec<RecipeSummary> {
    pack.recipes
        .iter()
        .map(|(name, r)| RecipeSummary {
            name: name.clone(),
            description: r.value.description.clone(),
            params: r.value.params.clone(),
            steps: r.value.steps.iter().map(|s| s.id().to_string()).collect(),
        })
        .collect()
}

/// Parses `--param k=v` pairs and checks them against the recipe's declared params. Every value
/// passes the query-value guard here, before any request (CT-31).
pub fn parse_params(
    recipe: &RecipeFile,
    raw: &[String],
) -> Result<BTreeMap<String, String>, SncfrError> {
    let mut params = BTreeMap::new();
    for kv in raw {
        let (k, v) = crate::mutate::parse_key_value_pair(kv)?;
        if !recipe.params.contains(&k) {
            return Err(SncfrError::InvalidArgs {
                message: format!(
                    "unknown recipe parameter '{}'",
                    crate::untrusted::inline(&k)
                ),
                remediation: Some(format!("This recipe takes: {}.", recipe.params.join(", "))),
            });
        }
        crate::untrusted::query_value(&v)?;
        params.insert(k, v);
    }
    let missing: Vec<&String> = recipe
        .params
        .iter()
        .filter(|p| !params.contains_key(*p))
        .collect();
    if !missing.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: format!(
                "missing recipe parameter(s): {}",
                missing
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            remediation: Some("Pass each with `--param name=value`.".to_string()),
        });
    }
    Ok(params)
}

/// Whether any later step refers to `{<id>.<field>}`.
fn is_referenced(steps: &[RecipeStep], idx: usize) -> bool {
    let needle = format!("{{{}.", steps[idx].id());
    steps[idx + 1..].iter().any(|s| match s {
        RecipeStep::Table { query, .. } | RecipeStep::Stats { query, .. } => {
            query.contains(&needle)
        }
        RecipeStep::Show { ticket, .. } => ticket.contains(&needle),
    })
}

/// Fills `{param}` and `{step.field}` in `template`. Each value passes the query-value guard;
/// after an `IN` operator a value may not contain `,` either (NA-10).
fn substitute(
    template: &str,
    params: &BTreeMap<String, String>,
    picked: &BTreeMap<String, Value>,
) -> Result<String, SncfrError> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 1..start + len];
        out.push_str(&rest[..start]);
        let value = match name.split_once('.') {
            Some((step, field)) => picked
                .get(step)
                .and_then(|row| extract_field_value(row, field))
                .ok_or_else(|| SncfrError::InvalidArgs {
                    message: format!("placeholder `{{{name}}}` names no earlier step's field"),
                    remediation: None,
                })?,
            None => params
                .get(name)
                .cloned()
                .ok_or_else(|| SncfrError::InvalidArgs {
                    message: format!("placeholder `{{{name}}}` names no recipe parameter"),
                    remediation: None,
                })?,
        };
        let checked = if out.ends_with("IN") {
            crate::untrusted::query_list_value(&value)?
        } else {
            crate::untrusted::query_value(&value)?
        };
        out.push_str(checked);
        rest = &rest[start + len + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn display_rows(rows: &[Value]) -> Vec<BTreeMap<String, String>> {
    rows.iter()
        .filter_map(Value::as_object)
        .map(|o| {
            o.keys()
                .filter_map(|k| {
                    let v = extract_field_display(&Value::Object(o.clone()), k)?;
                    Some((k.clone(), v))
                })
                .collect()
        })
        .collect()
}

/// Runs `recipe` step by step against a read-only client.
pub async fn run(
    name: &str,
    recipe: &RecipeFile,
    params: &BTreeMap<String, String>,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
) -> Result<RecipeOutput, SncfrError> {
    let mut picked: BTreeMap<String, Value> = BTreeMap::new();
    let mut steps = Vec::new();
    for (idx, step) in recipe.steps.iter().enumerate() {
        let referenced = is_referenced(&recipe.steps, idx);
        match step {
            RecipeStep::Table {
                id,
                table,
                query,
                fields,
                limit,
            } => {
                ensure_table(table)?;
                let q = substitute(query, params, &picked)?;
                // A step that feeds a later one is fetched with limit 2: one row or an error.
                let limit = if referenced {
                    2
                } else {
                    limit.unwrap_or(DEFAULT_LIMIT)
                }
                .to_string();
                let fields = fields.join(",");
                let mut query_params: Vec<(&str, &str)> = vec![
                    ("sysparm_query", q.as_str()),
                    ("sysparm_display_value", "all"),
                    ("sysparm_limit", limit.as_str()),
                ];
                if !fields.is_empty() {
                    query_params.push(("sysparm_fields", fields.as_str()));
                }
                let resp: Value = client
                    .get_json(&format!("/api/now/table/{table}"), &query_params)
                    .await?;
                let rows = resp
                    .get("result")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if referenced {
                    picked.insert(id.clone(), single_row(name, id, &rows)?);
                }
                steps.push(StepOutput {
                    id: id.clone(),
                    kind: "table".to_string(),
                    table: table.clone(),
                    query: q,
                    rows: display_rows(&rows),
                    ..Default::default()
                });
            }
            RecipeStep::Stats {
                id,
                table,
                query,
                group_by,
            } => {
                ensure_table(table)?;
                let q = substitute(query, params, &picked)?;
                let resp: Value = client
                    .get_json(
                        &format!("/api/now/stats/{table}"),
                        &[
                            ("sysparm_query", q.as_str()),
                            ("sysparm_group_by", group_by.as_str()),
                            ("sysparm_count", "true"),
                            ("sysparm_display_value", "all"),
                        ],
                    )
                    .await?;
                steps.push(StepOutput {
                    id: id.clone(),
                    kind: "stats".to_string(),
                    table: table.clone(),
                    query: q,
                    buckets: buckets(&resp, group_by),
                    ..Default::default()
                });
            }
            RecipeStep::Show { id, ticket } => {
                let t = substitute(ticket, params, &picked)?;
                let resolved = crate::resolve::resolve_ticket(client, cache, &t).await?;
                let fields = crate::dossier::default_dossier_fields(
                    crate::pack::active(),
                    &resolved.table,
                    &resolved.record,
                );
                let row: BTreeMap<String, String> = fields
                    .iter()
                    .filter_map(|f| {
                        let v = extract_field_display(&resolved.record, f)?;
                        (!v.is_empty()).then(|| (f.clone(), v))
                    })
                    .collect();
                if referenced {
                    picked.insert(id.clone(), resolved.record.clone());
                }
                steps.push(StepOutput {
                    id: id.clone(),
                    kind: "show".to_string(),
                    table: resolved.table,
                    query: t,
                    rows: vec![row],
                    ..Default::default()
                });
            }
        }
    }
    Ok(RecipeOutput {
        recipe: name.to_string(),
        params: params.clone(),
        steps,
    })
}

fn ensure_table(table: &str) -> Result<(), SncfrError> {
    if crate::untrusted::is_table_name(table) {
        Ok(())
    } else {
        Err(SncfrError::InvalidArgs {
            message: format!(
                "'{}' is not a valid table name",
                crate::untrusted::inline(table)
            ),
            remediation: Some("Fix the recipe in the pack (`sncfr pack validate`).".to_string()),
        })
    }
}

/// Exactly one row, or exit 2 without substituting (CT-31b/31c).
fn single_row(recipe: &str, step: &str, rows: &[Value]) -> Result<Value, SncfrError> {
    match rows {
        [one] => Ok(one.clone()),
        [] => Err(SncfrError::RecipeStepEmpty {
            recipe: recipe.to_string(),
            step: step.to_string(),
            detail: "no rows".to_string(),
        }),
        many => Err(SncfrError::AmbiguousReference {
            kind: format!("recipe step '{step}' row"),
            input: step.to_string(),
            detail: format!(
                "step '{step}' matched more than one row; a later step needs exactly one"
            ),
            candidates: many
                .iter()
                .filter_map(|r| {
                    extract_field_display(r, "name")
                        .or_else(|| extract_field_display(r, "number"))
                        .or_else(|| extract_field_value(r, "sys_id"))
                })
                .collect(),
            suggestion: None,
        }),
    }
}

fn buckets(resp: &Value, group_by: &str) -> Vec<crate::monitor::StatsBucket> {
    resp.get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            let count = item
                .pointer("/stats/count")
                .and_then(|c| {
                    c.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| c.as_u64())
                })
                .unwrap_or(0);
            let gf = item
                .get("groupby_fields")
                .and_then(Value::as_array)
                .and_then(|g| {
                    g.iter()
                        .find(|f| f.get("field").and_then(Value::as_str) == Some(group_by))
                });
            let value = gf
                .and_then(|f| f.get("value").and_then(Value::as_str))
                .unwrap_or("(empty)")
                .to_string();
            let display_value = gf
                .and_then(|f| f.get("display_value").and_then(Value::as_str))
                .filter(|d| !d.is_empty())
                .map_or_else(|| value.clone(), str::to_string);
            crate::monitor::StatsBucket {
                display_value,
                value,
                count,
            }
        })
        .collect()
}

pub fn format_recipe_list(recipes: &[RecipeSummary], format: ResolvedOutputFormat) -> String {
    if format == ResolvedOutputFormat::Json {
        return serde_json::to_string_pretty(recipes).unwrap_or_default();
    }
    if recipes.is_empty() {
        return "No recipes in the active Instance Pack.".to_string();
    }
    let mut out = String::new();
    for r in recipes {
        let params: Vec<String> = r.params.iter().map(|p| format!("--param {p}=…")).collect();
        let _ = writeln!(
            out,
            "- {}: {} [steps: {}] {}",
            crate::untrusted::inline(&r.name),
            crate::untrusted::inline(r.description.as_deref().unwrap_or("")),
            r.steps.join(" → "),
            params.join(" ")
        );
    }
    out
}

pub fn format_recipe_output(o: &RecipeOutput, format: ResolvedOutputFormat) -> String {
    if format == ResolvedOutputFormat::Json {
        return serde_json::to_string_pretty(o).unwrap_or_default();
    }
    let t = |s: &str| crate::untrusted::inline(s);
    let mut out = format!("Recipe {}\n", t(&o.recipe));
    for s in &o.steps {
        let _ = writeln!(out, "\n## {} ({} {})", t(&s.id), s.kind, t(&s.table));
        for row in &s.rows {
            let cells: Vec<String> = row.iter().map(|(k, v)| format!("{k}={}", t(v))).collect();
            let _ = writeln!(out, "- {}", cells.join(" · "));
        }
        for b in &s.buckets {
            let _ = writeln!(
                out,
                "- {} ({}): {}",
                t(&b.display_value),
                t(&b.value),
                b.count
            );
        }
        if s.rows.is_empty() && s.buckets.is_empty() {
            let _ = writeln!(out, "(no rows)");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn recipe() -> RecipeFile {
        let pack = crate::pack::parse_pack(include_str!("../docs/packs/example.pack.toml"))
            .expect("example pack");
        pack.recipes.expect("recipes")["ci-open-incidents"].clone()
    }

    #[test]
    fn a_param_cannot_change_the_query_structure() {
        // CT-31 (NA-10): rejected while parsing, before any request.
        let err = parse_params(&recipe(), &["host=x^NQactive=true".to_string()]).unwrap_err();
        assert_eq!(err.code().as_str(), "INVALID_QUERY_VALUE");
        assert_eq!(err.code().exit_code(), 2);
        assert!(parse_params(&recipe(), &[]).is_err(), "missing param");
        assert!(parse_params(&recipe(), &["nope=1".to_string(), "host=a".to_string()]).is_err());
    }

    async fn run_with_servers(servers: Value) -> (Result<RecipeOutput, SncfrError>, MockServer) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/cmdb_ci_server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": servers })))
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
        let r = recipe();
        let params = parse_params(&r, &["host=web-01".to_string()]).expect("params");
        (
            run("ci-open-incidents", &r, &params, &client, &cache).await,
            server,
        )
    }

    #[tokio::test]
    async fn a_step_feeding_a_later_one_needs_exactly_one_row() {
        // CT-31b, CT-31c (NA-10)
        let row = |id: &str| json!({ "sys_id": { "value": id }, "name": { "value": "web-01", "display_value": "web-01" } });
        for (rows, code) in [
            (
                json!([
                    row("f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"),
                    row("f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2")
                ]),
                "AMBIGUOUS_REFERENCE",
            ),
            (json!([]), "RECIPE_STEP_EMPTY"),
        ] {
            let (result, server) = run_with_servers(rows).await;
            let err = result.unwrap_err();
            assert_eq!(err.code().as_str(), code);
            assert_eq!(err.code().exit_code(), 2);
            let reqs = server.received_requests().await.unwrap_or_default();
            assert!(
                reqs.iter()
                    .all(|r| r.url.path() != "/api/now/table/task_ci"),
                "zero requests for step `inc`"
            );
            let q = reqs[0].url.query().unwrap_or_default().to_string();
            assert!(q.contains("sysparm_limit=2"), "{q}");
        }
    }
}
