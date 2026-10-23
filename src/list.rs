use crate::auth::resolve_current_identity;
use crate::cache::InstanceCache;
use crate::cli::{ListArgs, ListFilterArgs, SearchArgs, TableArgs};
use crate::client::{
    ReadOnlyClient, extract_field_display, extract_field_pair, extract_field_value,
};
use crate::config::{ResolvedProfile, SavedView};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::query::compile_list_filters;
use crate::resolve::{load_or_sync_prefixes, resolve_table_name};
use chrono::Utc;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const DEFAULT_TICKET_COLUMNS: &[&str] = &[
    "number",
    "sys_class_name",
    "state",
    "priority",
    "short_description",
    "assigned_to",
    "assignment_group",
    "sys_updated_on",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordListEnvelope {
    pub count: usize,
    pub table: String,
    pub query: String,
    pub limit: u32,
    pub offset: u32,
    #[serde(skip)]
    pub columns: Vec<String>,
    pub records: Vec<Value>,
}

/// Executes `sncfr list [@<view>] [flags]`.
pub async fn execute_list(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &ListArgs,
) -> Result<RecordListEnvelope, SncfrError> {
    let saved_view = match &args.view {
        Some(v) => Some(profile.resolve_saved_view(v)?),
        None => None,
    };
    execute_filtered_query(client, cache, &args.filters, saved_view, None, None, true).await
}

/// Executes `sncfr search <text> [flags]`.
pub async fn execute_search(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &SearchArgs,
) -> Result<RecordListEnvelope, SncfrError> {
    execute_filtered_query(
        client,
        cache,
        &args.filters,
        None,
        Some(args.text.as_str()),
        None,
        true,
    )
    .await
}

/// Executes `sncfr table <table_name> [flags]`.
pub async fn execute_table(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &TableArgs,
) -> Result<RecordListEnvelope, SncfrError> {
    execute_filtered_query(
        client,
        cache,
        &args.filters,
        None,
        None,
        Some(args.table_name.as_str()),
        false,
    )
    .await
}

async fn execute_filtered_query(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    filters: &ListFilterArgs,
    saved_view: Option<&SavedView>,
    search_text: Option<&str>,
    explicit_table_arg: Option<&str>,
    is_ticket_default: bool,
) -> Result<RecordListEnvelope, SncfrError> {
    let needs_identity = filters.mine
        || filters
            .assigned_to
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("@me"))
        || filters
            .opened_by
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("@me"))
        || filters
            .group
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("@my-groups"))
        || filters
            .watch_list
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("@me"));

    let identity = if needs_identity {
        resolve_current_identity(client, cache, false).await.ok()
    } else {
        cache.read_identity().ok().flatten()
    };

    let (compiled_table, mut eq) =
        compile_list_filters(filters, saved_view, identity.as_ref(), Utc::now())?;

    let prefixes = load_or_sync_prefixes(client, cache, false).await?;
    let raw_table = explicit_table_arg.unwrap_or(&compiled_table);
    let table = resolve_table_name(raw_table, &prefixes);

    if let Some(text) = search_text {
        eq.text_query(text);
    }

    // Default sort by `sys_updated_on` descending when no sort order was specified
    let mut query_str = eq.build();
    if !query_str.contains("ORDERBY") {
        eq.order_by_desc("sys_updated_on");
        query_str = eq.build();
    }

    let requested_columns: Vec<String> = if !filters.fields.is_empty() {
        filters
            .fields
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if let Some(view) = saved_view
        && !view.fields.is_empty()
    {
        view.fields.clone()
    } else if is_ticket_default {
        DEFAULT_TICKET_COLUMNS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        Vec::new()
    };

    let mut sysparm_fields_list = requested_columns.clone();
    if !sysparm_fields_list.is_empty() && !sysparm_fields_list.iter().any(|c| c == "sys_id") {
        sysparm_fields_list.push("sys_id".to_string());
    }
    let sysparm_fields = sysparm_fields_list.join(",");
    let limit_str = filters.limit.to_string();
    let offset_str = filters.offset.to_string();

    let mut query_params = vec![
        ("sysparm_query", query_str.as_str()),
        ("sysparm_limit", limit_str.as_str()),
        ("sysparm_offset", offset_str.as_str()),
        ("sysparm_display_value", "all"),
    ];
    if !sysparm_fields.is_empty() {
        query_params.push(("sysparm_fields", sysparm_fields.as_str()));
    }

    let path = format!("/api/now/table/{table}");
    let resp: Value = client.get_json(&path, &query_params).await?;
    let rows = resp
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let columns = if !requested_columns.is_empty() {
        requested_columns
    } else {
        infer_table_columns(&rows)
    };

    let base_url = client.base_url().as_str().trim_end_matches('/');
    let mut pruned_records = Vec::with_capacity(rows.len());

    for row in &rows {
        let mut obj = Map::new();
        if let Some(sys_id) = extract_field_value(row, "sys_id") {
            obj.insert("sys_id".to_string(), Value::String(sys_id.clone()));
            obj.insert(
                "ui_url".to_string(),
                Value::String(format!(
                    "{base_url}/nav_to.do?uri={table}.do?sys_id={sys_id}"
                )),
            );
        }

        if !columns.is_empty() {
            for col in &columns {
                if let Some((disp, raw)) = extract_field_pair(row, col) {
                    if disp == raw {
                        obj.insert(col.clone(), Value::String(disp));
                    } else {
                        obj.insert(
                            col.clone(),
                            json!({
                                "display_value": disp,
                                "value": raw
                            }),
                        );
                    }
                }
            }
        } else if let Some(raw_map) = row.as_object() {
            for k in raw_map.keys() {
                if let Some((disp, raw)) = extract_field_pair(row, k) {
                    if disp == raw {
                        obj.insert(k.clone(), Value::String(disp));
                    } else {
                        obj.insert(
                            k.clone(),
                            json!({
                                "display_value": disp,
                                "value": raw
                            }),
                        );
                    }
                }
            }
        }
        pruned_records.push(Value::Object(obj));
    }

    Ok(RecordListEnvelope {
        count: pruned_records.len(),
        table,
        query: query_str,
        limit: filters.limit,
        offset: filters.offset,
        columns,
        records: pruned_records,
    })
}

fn infer_table_columns(rows: &[Value]) -> Vec<String> {
    let preferred = [
        "number",
        "name",
        "user_name",
        "title",
        "short_description",
        "email",
        "state",
        "active",
        "sys_class_name",
        "sys_updated_on",
        "sys_id",
    ];
    let mut cols = Vec::new();
    let Some(first) = rows.first().and_then(Value::as_object) else {
        return preferred.iter().take(5).map(|s| (*s).to_string()).collect();
    };
    for p in preferred {
        if first.contains_key(p) {
            cols.push(p.to_string());
        }
    }
    for k in first.keys() {
        if cols.len() >= 8 {
            break;
        }
        if !cols.contains(k) && !k.starts_with("sys_") {
            cols.push(k.clone());
        }
    }
    cols
}

/// Formats a [`RecordListEnvelope`] according to `format`.
pub fn format_record_list(envelope: &RecordListEnvelope, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(envelope).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(envelope).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            out.push_str(&format!(
                "# `{}` ({} records)\n\n- **Query**: `{}`\n\n",
                envelope.table, envelope.count, envelope.query
            ));
            if envelope.records.is_empty() {
                out.push_str("_No matching records._\n");
                return out;
            }
            let headers: Vec<&str> = envelope.columns.iter().map(String::as_str).collect();
            out.push_str(&format!("| {} |\n", headers.join(" | ")));
            let sep: Vec<&str> = headers.iter().map(|_| ":---").collect();
            out.push_str(&format!("| {} |\n", sep.join(" | ")));
            for rec in &envelope.records {
                let cells: Vec<String> = envelope
                    .columns
                    .iter()
                    .map(|col| {
                        extract_field_display(rec, col)
                            .unwrap_or_default()
                            .replace('|', "\\|")
                            .replace('\n', " ")
                    })
                    .collect();
                out.push_str(&format!("| {} |\n", cells.join(" | ")));
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            if envelope.records.is_empty() {
                return format!(
                    "No records found in '{}' matching query `{}`.",
                    envelope.table, envelope.query
                );
            }
            let mut table = Table::new();
            let width = table.width().unwrap_or(140).max(140);
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width);
            table.set_header(
                envelope
                    .columns
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect::<Vec<_>>(),
            );

            for rec in &envelope.records {
                let row: Vec<String> = envelope
                    .columns
                    .iter()
                    .map(|col| extract_field_display(rec, col).unwrap_or_default())
                    .collect();
                table.add_row(row);
            }
            format!(
                "{table}\n({} records from '{}', offset={})",
                envelope.count, envelope.table, envelope.offset
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use crate::config::{AppConfig, AuthMethod, ProfileConfig, SavedView};
    use clap::Parser;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn executes_list_with_saved_view_and_formats_pruned_json_and_table() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .and(query_param(
                "sysparm_query",
                "assignment_group.name=Cloud Platform^active=true^priority=1^ORDERBYDESCsys_updated_on",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "inc_1", "display_value": "inc_1" },
                    "number": { "value": "INC0010099", "display_value": "INC0010099" },
                    "sys_class_name": { "value": "incident", "display_value": "Incident" },
                    "state": { "value": "2", "display_value": "In Progress" },
                    "priority": { "value": "1", "display_value": "1 - Critical" },
                    "short_description": { "value": "DB failover", "display_value": "DB failover" },
                    "assigned_to": { "value": "u1", "display_value": "Jane Doe" },
                    "assignment_group": { "value": "g1", "display_value": "Cloud Platform" },
                    "sys_updated_on": { "value": "2026-10-22 15:00:00", "display_value": "2026-10-22 15:00:00" }
                }]
            })))
            .mount(&server)
            .await;

        let mut views = BTreeMap::new();
        views.insert(
            "team-triage".to_string(),
            SavedView {
                table: "incident".to_string(),
                query: "assignment_group.name=Cloud Platform".to_string(),
                description: None,
                fields: vec![],
            },
        );
        let mut cfg = AppConfig {
            default_profile: Some("prod".to_string()),
            profiles: BTreeMap::new(),
        };
        cfg.profiles.insert(
            "prod".to_string(),
            ProfileConfig {
                instance: server.uri(),
                auth_method: AuthMethod::ApiKey,
                username: None,
                read_only: false,
                views,
            },
        );

        let cli = crate::cli::Cli::try_parse_from([
            "sncfr",
            "list",
            "@team-triage",
            "--active",
            "--priority",
            "1",
        ])
        .expect("parse list");
        let profile = cfg.resolve_profile(&cli).expect("profile");
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

        let crate::cli::Commands::List(list_args) = &cli.command else {
            panic!("expected list");
        };
        let env = execute_list(&profile, &client, &cache, list_args)
            .await
            .expect("execute list");
        assert_eq!(env.count, 1);
        assert_eq!(env.table, "incident");

        let tbl = format_record_list(&env, ResolvedOutputFormat::Table);
        assert!(tbl.contains("INC0010099"));
        assert!(tbl.contains("DB failover"));
    }
}
