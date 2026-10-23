use crate::auth::resolve_current_identity;
use crate::cache::InstanceCache;
use crate::cli::{AttachmentsArgs, FeedArgs, ListFilterArgs, StatsArgs};
use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::config::{ResolvedProfile, SavedView};
use crate::dossier::{AttachmentMeta, JournalEntry};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::query::{compile_list_filters, format_servicenow_gmt, parse_since_to_utc};
use crate::resolve::{load_or_sync_prefixes, resolve_table_name, resolve_ticket};
use chrono::Utc;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsBucket {
    pub display_value: String,
    pub value: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsEnvelope {
    pub table: String,
    pub group_by: String,
    pub query: String,
    pub total_count: u64,
    pub buckets: Vec<StatsBucket>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedTicketItem {
    pub number: String,
    pub table: String,
    pub sys_id: String,
    pub ui_url: String,
    pub state: String,
    pub priority: String,
    pub short_description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    pub updated_on: String,
    pub updated_by: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_entries: Vec<JournalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEnvelope {
    pub table: String,
    pub since: String,
    pub query: String,
    pub count: usize,
    #[serde(default)]
    pub degraded_inline_fallback: bool,
    pub items: Vec<FeedTicketItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadedAttachment {
    pub sys_id: String,
    pub file_name: String,
    pub saved_path: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentsEnvelope {
    pub ticket: String,
    pub table: String,
    pub ticket_sys_id: String,
    pub attachments: Vec<AttachmentMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloaded: Vec<DownloadedAttachment>,
}

/// Executes `sncfr stats [@<view>] [--by <field>] [flags]` against `/api/now/stats/{table}`.
pub async fn execute_stats(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &StatsArgs,
) -> Result<StatsEnvelope, SncfrError> {
    let saved_view = match &args.view {
        Some(v) => Some(profile.resolve_saved_view(v)?),
        None => None,
    };
    let (table, eq) = compile_table_and_query(client, cache, &args.filters, saved_view).await?;
    let query_str = eq.build();
    let group_field = args.by.field_name();

    let mut params = vec![
        ("sysparm_count", "true"),
        ("sysparm_group_by", group_field),
        ("sysparm_display_value", "all"),
    ];
    if !query_str.is_empty() {
        params.push(("sysparm_query", query_str.as_str()));
    }

    let path = format!("/api/now/stats/{table}");
    let resp: Value = client.get_json(&path, &params).await?;

    let mut buckets = Vec::new();
    let mut total_count = 0u64;

    if let Some(arr) = resp.get("result").and_then(Value::as_array) {
        for item in arr {
            let count = item
                .pointer("/stats/count")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| item.pointer("/stats/count").and_then(Value::as_u64))
                .unwrap_or(0);
            total_count += count;

            let mut val_str = "(empty)".to_string();
            let mut disp_str = "(empty)".to_string();
            if let Some(gf) = item
                .get("groupby_fields")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
            {
                if let Some(v) = gf.get("value").and_then(Value::as_str)
                    && !v.trim().is_empty()
                {
                    val_str = v.trim().to_string();
                }
                if let Some(dv) = gf.get("display_value").and_then(Value::as_str)
                    && !dv.trim().is_empty()
                {
                    disp_str = dv.trim().to_string();
                } else if val_str != "(empty)" {
                    disp_str = val_str.clone();
                }
            }

            buckets.push(StatsBucket {
                display_value: disp_str,
                value: val_str,
                count,
            });
        }
    } else if let Some(single_count) = resp
        .pointer("/result/stats/count")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok())
    {
        total_count = single_count;
    }

    buckets.sort_by(|a, b| b.count.cmp(&a.count));

    Ok(StatsEnvelope {
        table,
        group_by: group_field.to_string(),
        query: query_str,
        total_count,
        buckets,
    })
}

/// Executes `sncfr feed [@<view>] [--since <duration>] [flags]`.
pub async fn execute_feed(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &FeedArgs,
) -> Result<FeedEnvelope, SncfrError> {
    let saved_view = match &args.view {
        Some(v) => Some(profile.resolve_saved_view(v)?),
        None => None,
    };
    let now = Utc::now();
    let since_dt = parse_since_to_utc(&args.since, now)?;
    let since_gmt = format_servicenow_gmt(since_dt);

    let (table, mut eq) = compile_table_and_query(client, cache, &args.filters, saved_view).await?;
    if args.filters.updated_since.is_none() {
        eq.gte("sys_updated_on", &since_gmt);
    }
    let mut query_str = eq.build();
    if !query_str.contains("ORDERBY") {
        eq.order_by_desc("sys_updated_on");
        query_str = eq.build();
    }

    let limit_str = args.filters.limit.to_string();
    let offset_str = args.filters.offset.to_string();
    let fields = "sys_id,number,sys_class_name,state,priority,short_description,assigned_to,sys_updated_on,sys_updated_by,comments_and_work_notes,comments";

    let path = format!("/api/now/table/{table}");
    let resp: Value = client
        .get_json(
            &path,
            &[
                ("sysparm_query", query_str.as_str()),
                ("sysparm_limit", limit_str.as_str()),
                ("sysparm_offset", offset_str.as_str()),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", fields),
            ],
        )
        .await?;

    let rows = resp
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let sys_ids: Vec<String> = rows
        .iter()
        .filter_map(|r| extract_field_value(r, "sys_id"))
        .collect();

    let mut journal_by_ticket: BTreeMap<String, Vec<JournalEntry>> = BTreeMap::new();
    let mut degraded_inline_fallback = false;

    if !sys_ids.is_empty() {
        let j_query = format!(
            "element_idIN{}^elementINcomments,work_notes^sys_created_on>={since_gmt}^ORDERBYDESCsys_created_on",
            sys_ids.join(",")
        );
        match client
            .get_json::<Value>(
                "/api/now/table/sys_journal_field",
                &[
                    ("sysparm_query", j_query.as_str()),
                    ("sysparm_display_value", "all"),
                    (
                        "sysparm_fields",
                        "element_id,element,value,sys_created_on,sys_created_by",
                    ),
                    ("sysparm_limit", "200"),
                ],
            )
            .await
        {
            Ok(j_resp) => {
                if let Some(j_rows) = j_resp.get("result").and_then(Value::as_array) {
                    for jr in j_rows {
                        if let (Some(elem_id), Some(body)) = (
                            extract_field_value(jr, "element_id"),
                            extract_field_display(jr, "value"),
                        ) {
                            journal_by_ticket
                                .entry(elem_id)
                                .or_default()
                                .push(JournalEntry {
                                    element: extract_field_value(jr, "element")
                                        .unwrap_or_else(|| "comments".to_string()),
                                    author: extract_field_display(jr, "sys_created_by")
                                        .unwrap_or_else(|| "system".to_string()),
                                    timestamp: extract_field_display(jr, "sys_created_on")
                                        .unwrap_or_default(),
                                    body,
                                });
                        }
                    }
                }
            }
            Err(_) => {
                degraded_inline_fallback = true;
            }
        }
    }

    let base_url = client.base_url().as_str().trim_end_matches('/');
    let mut items = Vec::with_capacity(rows.len());

    for row in &rows {
        let Some(sys_id) = extract_field_value(row, "sys_id") else {
            continue;
        };
        let number = extract_field_display(row, "number").unwrap_or_else(|| sys_id.clone());
        let row_table = extract_field_value(row, "sys_class_name").unwrap_or_else(|| table.clone());
        let mut recent_entries = journal_by_ticket.remove(&sys_id).unwrap_or_default();

        if degraded_inline_fallback
            && recent_entries.is_empty()
            && let Some(inline) = extract_field_display(row, "comments_and_work_notes")
                .or_else(|| extract_field_display(row, "comments"))
            && let Some(first_block) = inline.split("\n\n").next()
            && !first_block.trim().is_empty()
        {
            recent_entries.push(JournalEntry {
                element: "comments".to_string(),
                author: "inline".to_string(),
                timestamp: String::new(),
                body: first_block.trim().to_string(),
            });
        }

        items.push(FeedTicketItem {
            number,
            ui_url: format!("{base_url}/nav_to.do?uri={row_table}.do?sys_id={sys_id}"),
            table: row_table,
            sys_id,
            state: extract_field_display(row, "state").unwrap_or_else(|| "Unknown".to_string()),
            priority: extract_field_display(row, "priority").unwrap_or_default(),
            short_description: extract_field_display(row, "short_description").unwrap_or_default(),
            assigned_to: extract_field_display(row, "assigned_to"),
            updated_on: extract_field_display(row, "sys_updated_on").unwrap_or_default(),
            updated_by: extract_field_display(row, "sys_updated_by").unwrap_or_default(),
            recent_entries,
        });
    }

    Ok(FeedEnvelope {
        table,
        since: args.since.clone(),
        query: query_str,
        count: items.len(),
        degraded_inline_fallback,
        items,
    })
}

/// Executes `sncfr attachments <TICKET> [--download [file_or_sysid]] [--out-dir <dir>]`.
pub async fn execute_attachments(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &AttachmentsArgs,
) -> Result<AttachmentsEnvelope, SncfrError> {
    let resolved = resolve_ticket(client, cache, &args.ticket).await?;
    let q = format!("table_sys_id={}^ORDERBYsys_created_on", resolved.sys_id);
    let resp: Value = client
        .get_json(
            "/api/now/table/sys_attachment",
            &[
                ("sysparm_query", q.as_str()),
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "sys_id,file_name,content_type,size_bytes,sys_created_by,sys_created_on",
                ),
                ("sysparm_limit", "100"),
            ],
        )
        .await?;

    let mut attachments = Vec::new();
    if let Some(rows) = resp.get("result").and_then(Value::as_array) {
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
                    created_by: extract_field_display(row, "sys_created_by").unwrap_or_default(),
                    created_on: extract_field_display(row, "sys_created_on").unwrap_or_default(),
                });
            }
        }
    }

    let mut downloaded = Vec::new();
    if let Some(target_filter) = &args.download {
        let out_dir = args.out_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&out_dir).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to create attachment output directory '{}': {e}",
                out_dir.display()
            ),
            remediation: None,
        })?;

        let matching: Vec<&AttachmentMeta> = attachments
            .iter()
            .filter(|a| {
                target_filter == "*"
                    || a.sys_id == *target_filter
                    || a.file_name.eq_ignore_ascii_case(target_filter)
            })
            .collect();

        if matching.is_empty() {
            return Err(SncfrError::NotFound {
                identifier: format!("attachment '{}' on {}", target_filter, resolved.number),
                table: Some("sys_attachment".to_string()),
            });
        }

        for att in matching {
            let dl_path = format!("/api/now/attachment/{}/file", att.sys_id);
            let bytes = client.get_bytes(&dl_path, &[]).await?;
            let safe_name = sanitize_attachment_name(&att.file_name);
            let dest = out_dir.join(&safe_name);
            fs::write(&dest, &bytes).map_err(|e| SncfrError::InvalidArgs {
                message: format!("Failed to write attachment to '{}': {e}", dest.display()),
                remediation: None,
            })?;
            downloaded.push(DownloadedAttachment {
                sys_id: att.sys_id.clone(),
                file_name: att.file_name.clone(),
                saved_path: dest.display().to_string(),
                size_bytes: bytes.len(),
            });
        }
    }

    Ok(AttachmentsEnvelope {
        ticket: resolved.number,
        table: resolved.table,
        ticket_sys_id: resolved.sys_id,
        attachments,
        downloaded,
    })
}

fn sanitize_attachment_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or("attachment.bin")
        .to_string()
}

async fn compile_table_and_query(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    filters: &ListFilterArgs,
    saved_view: Option<&SavedView>,
) -> Result<(String, crate::query::EncodedQuery), SncfrError> {
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

    let (compiled_table, eq) =
        compile_list_filters(filters, saved_view, identity.as_ref(), Utc::now())?;
    let prefixes = load_or_sync_prefixes(client, cache, false).await?;
    let table = resolve_table_name(&compiled_table, &prefixes);
    Ok((table, eq))
}

pub fn format_stats(env: &StatsEnvelope, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(env).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(env).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            out.push_str(&format!(
                "# Stats: `{}` grouped by `{}` (Total: {})\n\n",
                env.table, env.group_by, env.total_count
            ));
            out.push_str("| Group | Value | Count |\n| :--- | :--- | ---: |\n");
            for b in &env.buckets {
                out.push_str(&format!(
                    "| {} | `{}` | {} |\n",
                    b.display_value, b.value, b.count
                ));
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    env.group_by.to_ascii_uppercase().as_str(),
                    "RAW_VALUE",
                    "COUNT",
                ]);
            for b in &env.buckets {
                table.add_row(vec![
                    b.display_value.as_str(),
                    b.value.as_str(),
                    &b.count.to_string(),
                ]);
            }
            format!(
                "{table}\n(Total: {} across '{}' grouped by '{}')",
                env.total_count, env.table, env.group_by
            )
        }
    }
}

pub fn format_feed(env: &FeedEnvelope, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(env).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(env).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            out.push_str(&format!(
                "# Activity Feed — `{}` (since `{}`, {} tickets)\n\n",
                env.table, env.since, env.count
            ));
            if env.items.is_empty() {
                out.push_str("_No ticket activity in this window._\n");
                return out;
            }
            for item in &env.items {
                out.push_str(&format!(
                    "## {} (`{}`) — {}\n- **State**: {} | **Updated**: {} by `{}`\n- **URL**: {}\n",
                    item.number,
                    item.table,
                    item.short_description,
                    item.state,
                    item.updated_on,
                    item.updated_by,
                    item.ui_url
                ));
                for entry in &item.recent_entries {
                    out.push_str(&format!(
                        "  - **[{} | `{}`]**: {}\n",
                        entry.element, entry.author, entry.body
                    ));
                }
                out.push('\n');
            }
            out
        }
        ResolvedOutputFormat::TerminalDossier | ResolvedOutputFormat::Table => {
            let mut out = String::new();
            out.push_str(&format!(
                "Activity Feed — '{}' (since {}, {} tickets updated)\n\n",
                env.table, env.since, env.count
            ));
            for item in &env.items {
                out.push_str(&format!(
                    "{} [{}] ({}) — {}\n  Updated: {} by {}\n",
                    item.number,
                    item.table,
                    item.state,
                    item.short_description,
                    item.updated_on,
                    item.updated_by
                ));
                for entry in &item.recent_entries {
                    out.push_str(&format!(
                        "  > [{} | {}]: {}\n",
                        entry.element, entry.author, entry.body
                    ));
                }
                out.push('\n');
            }
            out
        }
    }
}

pub fn format_attachments(env: &AttachmentsEnvelope, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(env).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(env).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            out.push_str(&format!(
                "# Attachments for {} (`{}`)\n\n",
                env.ticket, env.table
            ));
            for att in &env.attachments {
                out.push_str(&format!(
                    "- **`{}`** ({} bytes, `{}`, `sys_id={}`)\n",
                    att.file_name, att.size_bytes, att.content_type, att.sys_id
                ));
            }
            if !env.downloaded.is_empty() {
                out.push_str("\n## Downloaded\n\n");
                for dl in &env.downloaded {
                    out.push_str(&format!(
                        "- Saved `{}` -> `{}` ({} bytes)\n",
                        dl.file_name, dl.saved_path, dl.size_bytes
                    ));
                }
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            if env.attachments.is_empty() {
                return format!("No attachments found on {}.", env.ticket);
            }
            let mut table = Table::new();
            let width = table.width().unwrap_or(120).max(120);
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width)
                .set_header(vec![
                    "SYS_ID",
                    "FILE_NAME",
                    "CONTENT_TYPE",
                    "BYTES",
                    "CREATED_BY",
                    "CREATED_ON",
                ]);
            for att in &env.attachments {
                table.add_row(vec![
                    att.sys_id.as_str(),
                    att.file_name.as_str(),
                    att.content_type.as_str(),
                    &att.size_bytes.to_string(),
                    att.created_by.as_str(),
                    att.created_on.as_str(),
                ]);
            }
            let mut out = table.to_string();
            for dl in &env.downloaded {
                out.push_str(&format!(
                    "\nDownloaded '{}' -> '{}' ({} bytes)",
                    dl.file_name, dl.saved_path, dl.size_bytes
                ));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::StatsGroupBy;
    use crate::client::ClientAuth;
    use crate::config::{AppConfig, AuthMethod, ProfileConfig};
    use clap::Parser;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn executes_stats_and_downloads_attachments_cleanly() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        // 1. Mock `/api/now/stats/incident`
        Mock::given(method("GET"))
            .and(path("/api/now/stats/incident"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [
                    {
                        "stats": { "count": "12" },
                        "groupby_fields": [{ "field": "state", "value": "2", "display_value": "In Progress" }]
                    },
                    {
                        "stats": { "count": "3" },
                        "groupby_fields": [{ "field": "state", "value": "1", "display_value": "New" }]
                    }
                ]
            })))
            .mount(&server)
            .await;

        // 2. Mock `INC0010042` & `sys_attachment` & `/api/now/attachment/att_1/file`
        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "inc_42", "display_value": "inc_42" },
                    "number": { "value": "INC0010042", "display_value": "INC0010042" },
                    "sys_class_name": { "value": "incident", "display_value": "Incident" }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_attachment"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "att_1", "display_value": "att_1" },
                    "file_name": { "value": "crash.log", "display_value": "crash.log" },
                    "content_type": { "value": "text/plain", "display_value": "text/plain" },
                    "size_bytes": { "value": "11", "display_value": "11" },
                    "sys_created_by": { "value": "alice", "display_value": "Alice" },
                    "sys_created_on": { "value": "2026-10-22 12:00:00", "display_value": "2026-10-22 12:00:00" }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/attachment/att_1/file"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
            .mount(&server)
            .await;

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
                views: BTreeMap::new(),
            },
        );
        let cli = crate::cli::Cli::try_parse_from(["sncfr", "stats", "--table", "inc"])
            .expect("parse stats");
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

        let stats_args = StatsArgs {
            view: None,
            by: StatsGroupBy::State,
            filters: ListFilterArgs {
                table: Some("inc".to_string()),
                ..Default::default()
            },
        };
        let stats_env = execute_stats(&profile, &client, &cache, &stats_args)
            .await
            .expect("execute stats");
        assert_eq!(stats_env.total_count, 15);
        assert_eq!(stats_env.buckets[0].display_value, "In Progress");
        assert_eq!(stats_env.buckets[0].count, 12);

        let dl_dir = dir.path().join("downloads");
        let att_args = AttachmentsArgs {
            ticket: "INC0010042".to_string(),
            download: Some("*".to_string()),
            out_dir: Some(dl_dir.clone()),
        };
        let att_env = execute_attachments(&client, &cache, &att_args)
            .await
            .expect("execute attachments");
        assert_eq!(att_env.downloaded.len(), 1);
        let saved_bytes =
            fs::read_to_string(dl_dir.join("crash.log")).expect("read downloaded file");
        assert_eq!(saved_bytes, "hello world");
    }
}
