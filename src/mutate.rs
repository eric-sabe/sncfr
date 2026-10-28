use crate::auth::resolve_current_identity;
use crate::cache::InstanceCache;
use crate::cli::{AttachArgs, CommentArgs, CreateArgs, UpdateArgs};
use crate::client::{
    ReadOnlyClient, WritePermit, extract_field_display, extract_field_pair, extract_field_value,
};
use crate::error::SncfrError;
use crate::output::{ResolvedOutputFormat, osc8_link};
use crate::resolve::{is_sys_id, load_or_sync_prefixes, resolve_table_name, resolve_ticket};
use crate::resolve_value::{ResolveCtx, resolve_choice, resolve_field};
use crate::schema::load_or_sync_table_schema;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_value: Option<String>,
    pub after_display: String,
    pub after_value: String,
    /// Where the value was confirmed (SAFE-2): `pack`, `ootb`, `cache`, `sys_choice`,
    /// `discovered`, `input` (free text), a reference resolution such as `group:exact`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `verified`, `verified (in-use set)`, `UNVERIFIABLE (<reason>)`, `allowed unverified
    /// (<reason>)`, or `n/a (free text)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Details when the value could not be confirmed (SAFE-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverifiable: Option<UnverifiableField>,
}

/// A value that could not be confirmed against an active pack or instance metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiableField {
    pub field: String,
    pub input: String,
    pub would_send: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<String>,
}

impl FieldDiff {
    /// A diff row for a resolved value, carrying its source and verification status.
    pub fn from_resolved(
        field: &str,
        before: Option<(String, String)>,
        input: &str,
        resolved: &crate::resolve_value::ResolvedValue,
    ) -> Self {
        Self {
            field: field.to_string(),
            before_display: before.as_ref().map(|b| b.0.clone()),
            before_value: before.as_ref().map(|b| b.1.clone()),
            after_display: resolved.display(),
            after_value: resolved.value().to_string(),
            source: Some(resolved.source_label()),
            status: Some(resolved.status_label()),
            unverifiable: resolved.unverifiable().map(|reason| UnverifiableField {
                field: field.to_string(),
                input: input.to_string(),
                would_send: resolved.value().to_string(),
                reason: reason.as_str().to_string(),
                candidates: resolved
                    .candidates()
                    .iter()
                    .map(|(v, l)| format!("{l} ({v})"))
                    .collect(),
                suggested: resolved.suggested().map(str::to_string),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMutationItem {
    pub file_name: String,
    pub local_path: String,
    pub content_type: String,
    pub size_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_sys_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationReport {
    /// `"dry_run"` or `"committed"`.
    pub mode: String,
    /// `"comment"`, `"note"`, `"update"`, `"create"`, or `"attach"`.
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    pub table: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sys_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diffs: Vec<FieldDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentMutationItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_command: Option<String>,
}

/// Executes `sncfr comment` (`is_work_note = false`) or `sncfr note` (`is_work_note = true`).
/// Runs as a Validated Dry-Run Preview when `permit` is `None`.
pub async fn execute_comment_or_note(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &CommentArgs,
    is_work_note: bool,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let body_text = resolve_message_body(args)?;
    let resolved = resolve_ticket(&client, cache, &args.ticket).await?;
    let field_name = if is_work_note {
        "work_notes"
    } else {
        "comments"
    };
    let op_name = if is_work_note { "note" } else { "comment" };
    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();
    let ui_url = format!(
        "{base_url}/nav_to.do?uri={}.do?sys_id={}",
        resolved.table, resolved.sys_id
    );

    let diff = FieldDiff {
        field: field_name.to_string(),
        before_display: None,
        before_value: None,
        after_display: body_text.clone(),
        after_value: body_text.clone(),
        ..Default::default()
    };

    if let Some(write_permit) = permit {
        let mutating = client.into_mutating(write_permit);
        let mut payload = Map::new();
        payload.insert(field_name.to_string(), Value::String(body_text));
        let path = format!("/api/now/table/{}/{}", resolved.table, resolved.sys_id);
        let _: Value = mutating
            .patch_json(&path, &[("sysparm_display_value", "all")], &payload)
            .await?;

        Ok(MutationReport {
            mode: "committed".to_string(),
            operation: op_name.to_string(),
            ticket: Some(resolved.number),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs: vec![diff],
            attachments: vec![],
            commit_command: None,
        })
    } else {
        let commit_cmd = if let Some(file) = &args.file {
            format!(
                "sncfr {op_name} {} --file {} --write",
                shell_quote(&resolved.number),
                shell_quote(&file.display().to_string())
            )
        } else {
            format!(
                "sncfr {op_name} {} {} --write",
                shell_quote(&resolved.number),
                shell_quote(&body_text)
            )
        };
        Ok(MutationReport {
            mode: "dry_run".to_string(),
            operation: op_name.to_string(),
            ticket: Some(resolved.number),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs: vec![diff],
            attachments: vec![],
            commit_command: Some(commit_cmd),
        })
    }
}

/// Executes `sncfr update <TICKET> [flags] [--write]`.
pub async fn execute_update(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &UpdateArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let resolved = resolve_ticket(&client, cache, &args.ticket).await?;
    let schema = load_or_sync_table_schema(&client, cache, &resolved.table, false).await?;
    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();
    let ui_url = format!(
        "{base_url}/nav_to.do?uri={}.do?sys_id={}",
        resolved.table, resolved.sys_id
    );

    let ctx = ResolveCtx {
        pack: crate::pack::active(),
        table: &resolved.table,
        schema: &schema,
        sample: Some(&resolved.record),
        discovered: None,
    };
    let mut diffs = Vec::new();
    let mut payload = Map::new();

    // 1. Choice fields (`state`, `priority`, `urgency`, `impact`, `close_code`)
    for (field, opt_val) in [
        ("state", &args.state),
        ("priority", &args.priority),
        ("urgency", &args.urgency),
        ("impact", &args.impact),
        ("close_code", &args.close_code),
    ] {
        if let Some(input_val) = opt_val {
            let value = resolve_choice(&ctx, field, input_val)?;
            let before = extract_field_pair(&resolved.record, field);
            diffs.push(FieldDiff::from_resolved(field, before, input_val, &value));
            payload.insert(field.to_string(), Value::String(value.value().to_string()));
        }
    }

    // 2. User & Group Reference fields (`assigned_to`, `assignment_group`)
    if let Some(assign_to) = &args.assign_to {
        let (after_disp, after_val) = resolve_user_reference(&client, cache, assign_to).await?;
        let before = extract_field_pair(&resolved.record, "assigned_to");
        diffs.push(FieldDiff {
            field: "assigned_to".to_string(),
            before_display: before.as_ref().map(|b| b.0.clone()),
            before_value: before.as_ref().map(|b| b.1.clone()),
            after_display: after_disp,
            after_value: after_val.clone(),
            ..Default::default()
        });
        payload.insert("assigned_to".to_string(), Value::String(after_val));
    }

    if let Some(group) = &args.group {
        let (after_disp, after_val) = resolve_group_reference(&client, cache, group).await?;
        let before = extract_field_pair(&resolved.record, "assignment_group");
        diffs.push(FieldDiff {
            field: "assignment_group".to_string(),
            before_display: before.as_ref().map(|b| b.0.clone()),
            before_value: before.as_ref().map(|b| b.1.clone()),
            after_display: after_disp,
            after_value: after_val.clone(),
            ..Default::default()
        });
        payload.insert("assignment_group".to_string(), Value::String(after_val));
    }

    // 3. Text fields (`short_description`, `description`, `close_notes`, `work_notes`, `comments`)
    for (field, opt_val) in [
        ("short_description", &args.short_description),
        ("description", &args.description),
        ("close_notes", &args.close_notes),
        ("work_notes", &args.note),
        ("comments", &args.comment),
    ] {
        if let Some(val) = opt_val {
            let before = if field == "work_notes" || field == "comments" {
                None
            } else {
                extract_field_pair(&resolved.record, field)
            };
            diffs.push(FieldDiff {
                field: field.to_string(),
                before_display: before.as_ref().map(|b| b.0.clone()),
                before_value: before.as_ref().map(|b| b.1.clone()),
                after_display: val.clone(),
                after_value: val.clone(),
                source: Some("input".to_string()),
                status: Some("n/a (free text)".to_string()),
                ..Default::default()
            });
            payload.insert(field.to_string(), Value::String(val.clone()));
        }
    }

    // 4. Arbitrary `--set field=value` pairs
    for kv in &args.set_fields {
        let (k, v) = parse_key_value_pair(kv)?;
        let value = resolve_field(&ctx, &k, &v)?;
        let before = extract_field_pair(&resolved.record, &k);
        diffs.push(FieldDiff::from_resolved(&k, before, &v, &value));
        payload.insert(k, Value::String(value.value().to_string()));
    }

    if payload.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "No field updates were specified for `sncfr update`".to_string(),
            remediation: Some(
                "Pass at least one field flag (e.g., `--state`, `--assign-to`, `--priority`, `--set key=value`)."
                    .to_string(),
            ),
        });
    }

    if let Some(write_permit) = permit {
        let mutating = client.into_mutating(write_permit);
        let path = format!("/api/now/table/{}/{}", resolved.table, resolved.sys_id);
        let _: Value = mutating
            .patch_json(&path, &[("sysparm_display_value", "all")], &payload)
            .await?;

        Ok(MutationReport {
            mode: "committed".to_string(),
            operation: "update".to_string(),
            ticket: Some(resolved.number),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs,
            attachments: vec![],
            commit_command: None,
        })
    } else {
        Ok(MutationReport {
            mode: "dry_run".to_string(),
            operation: "update".to_string(),
            ticket: Some(resolved.number.clone()),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs,
            attachments: vec![],
            commit_command: Some(build_update_commit_command(&resolved.number, args)),
        })
    }
}

/// Executes `sncfr create <table|prefix> [flags] [--write]`.
pub async fn execute_create(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &CreateArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let prefixes = load_or_sync_prefixes(&client, cache, false).await?;
    let table = resolve_table_name(&args.table_or_prefix, &prefixes);
    let schema = load_or_sync_table_schema(&client, cache, &table, false).await?;
    let ctx = ResolveCtx {
        pack: crate::pack::active(),
        table: &table,
        schema: &schema,
        sample: None,
        discovered: None,
    };

    let mut diffs = Vec::new();
    let mut payload = Map::new();

    diffs.push(FieldDiff {
        field: "short_description".to_string(),
        before_display: None,
        before_value: None,
        after_display: args.short_description.clone(),
        after_value: args.short_description.clone(),
        ..Default::default()
    });
    payload.insert(
        "short_description".to_string(),
        Value::String(args.short_description.clone()),
    );

    if let Some(desc) = &args.description {
        diffs.push(FieldDiff {
            field: "description".to_string(),
            before_display: None,
            before_value: None,
            after_display: desc.clone(),
            after_value: desc.clone(),
            ..Default::default()
        });
        payload.insert("description".to_string(), Value::String(desc.clone()));
    }

    for (field, opt_val) in [
        ("priority", &args.priority),
        ("urgency", &args.urgency),
        ("impact", &args.impact),
    ] {
        if let Some(input_val) = opt_val {
            let value = resolve_choice(&ctx, field, input_val)?;
            diffs.push(FieldDiff::from_resolved(field, None, input_val, &value));
            payload.insert(field.to_string(), Value::String(value.value().to_string()));
        }
    }

    if let Some(assign_to) = &args.assign_to {
        let (after_disp, after_val) = resolve_user_reference(&client, cache, assign_to).await?;
        diffs.push(FieldDiff {
            field: "assigned_to".to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp,
            after_value: after_val.clone(),
            ..Default::default()
        });
        payload.insert("assigned_to".to_string(), Value::String(after_val));
    }

    if let Some(group) = &args.group {
        let (after_disp, after_val) = resolve_group_reference(&client, cache, group).await?;
        diffs.push(FieldDiff {
            field: "assignment_group".to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp,
            after_value: after_val.clone(),
            ..Default::default()
        });
        payload.insert("assignment_group".to_string(), Value::String(after_val));
    }

    if let Some(caller) = &args.caller {
        let (after_disp, after_val) = resolve_user_reference(&client, cache, caller).await?;
        let caller_field = crate::pack::active().caller_field(&table);
        diffs.push(FieldDiff {
            field: caller_field.to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp,
            after_value: after_val.clone(),
            ..Default::default()
        });
        payload.insert(caller_field.to_string(), Value::String(after_val));
    }

    for kv in &args.set_fields {
        let (k, v) = parse_key_value_pair(kv)?;
        let value = resolve_field(&ctx, &k, &v)?;
        diffs.push(FieldDiff::from_resolved(&k, None, &v, &value));
        payload.insert(k, Value::String(value.value().to_string()));
    }

    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();

    if let Some(write_permit) = permit {
        let mutating = client.into_mutating(write_permit);
        let path = format!("/api/now/table/{table}");
        let resp: Value = mutating
            .post_json(&path, &[("sysparm_display_value", "all")], &payload)
            .await?;
        let created = resp.get("result").unwrap_or(&resp);
        let sys_id = extract_field_value(created, "sys_id");
        let number = extract_field_display(created, "number");
        let ui_url = sys_id
            .as_ref()
            .map(|id| format!("{base_url}/nav_to.do?uri={table}.do?sys_id={id}"));

        Ok(MutationReport {
            mode: "committed".to_string(),
            operation: "create".to_string(),
            ticket: number,
            table,
            sys_id,
            ui_url,
            diffs,
            attachments: vec![],
            commit_command: None,
        })
    } else {
        Ok(MutationReport {
            mode: "dry_run".to_string(),
            operation: "create".to_string(),
            ticket: None,
            table: table.clone(),
            sys_id: None,
            ui_url: None,
            diffs,
            attachments: vec![],
            commit_command: Some(build_create_commit_command(&table, args)),
        })
    }
}

/// Executes `sncfr attach <TICKET> <FILE_PATH>... [--write]`.
pub async fn execute_attach(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &AttachArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let resolved = resolve_ticket(&client, cache, &args.ticket).await?;
    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();
    let ui_url = format!(
        "{base_url}/nav_to.do?uri={}.do?sys_id={}",
        resolved.table, resolved.sys_id
    );

    let mut prepared_files: Vec<(String, String, String, Vec<u8>)> =
        Vec::with_capacity(args.files.len());
    for file_path in &args.files {
        let bytes = fs::read(file_path).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to read attachment file '{}': {e}",
                file_path.display()
            ),
            remediation: None,
        })?;
        let file_name = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| SncfrError::InvalidArgs {
                message: format!("Invalid file name in path '{}'", file_path.display()),
                remediation: None,
            })?
            .to_string();
        let content_type = guess_content_type(file_path).to_string();
        prepared_files.push((
            file_name,
            file_path.display().to_string(),
            content_type,
            bytes,
        ));
    }

    if let Some(write_permit) = permit {
        let mutating = client.into_mutating(write_permit);
        let mut items = Vec::with_capacity(prepared_files.len());
        for (file_name, local_path, content_type, bytes) in prepared_files {
            let size_bytes = bytes.len();
            let resp: Value = mutating
                .upload_attachment(
                    &resolved.table,
                    &resolved.sys_id,
                    &file_name,
                    &content_type,
                    bytes,
                )
                .await?;
            let att_sys_id = resp
                .get("result")
                .and_then(|r| extract_field_value(r, "sys_id"));
            items.push(AttachmentMutationItem {
                file_name,
                local_path,
                content_type,
                size_bytes,
                attachment_sys_id: att_sys_id,
            });
        }

        Ok(MutationReport {
            mode: "committed".to_string(),
            operation: "attach".to_string(),
            ticket: Some(resolved.number),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs: vec![],
            attachments: items,
            commit_command: None,
        })
    } else {
        let items: Vec<AttachmentMutationItem> = prepared_files
            .into_iter()
            .map(
                |(file_name, local_path, content_type, bytes)| AttachmentMutationItem {
                    file_name,
                    local_path,
                    content_type,
                    size_bytes: bytes.len(),
                    attachment_sys_id: None,
                },
            )
            .collect();

        Ok(MutationReport {
            mode: "dry_run".to_string(),
            operation: "attach".to_string(),
            ticket: Some(resolved.number.clone()),
            table: resolved.table,
            sys_id: Some(resolved.sys_id),
            ui_url: Some(ui_url),
            diffs: vec![],
            attachments: items,
            commit_command: Some(build_attach_commit_command(&resolved.number, args)),
        })
    }
}

pub async fn resolve_user_reference(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<(String, String), SncfrError> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("unassigned")
    {
        return Ok(("(unassigned)".to_string(), String::new()));
    }
    if trimmed.eq_ignore_ascii_case("@me") {
        let identity = resolve_current_identity(client, cache, false).await?;
        return Ok((identity.display_name, identity.sys_id));
    }
    if is_sys_id(trimmed) {
        return Ok((trimmed.to_string(), trimmed.to_string()));
    }

    let trimmed = crate::untrusted::query_value(trimmed)?;
    let q = format!("user_name={trimmed}^ORemail={trimmed}^ORname={trimmed}");
    let resp: Value = client
        .get_json(
            "/api/now/table/sys_user",
            &[
                ("sysparm_query", q.as_str()),
                ("sysparm_limit", "2"),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "sys_id,name,user_name"),
            ],
        )
        .await?;

    if let Some(first) = resp
        .get("result")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        && let Some(sys_id) = extract_field_value(first, "sys_id")
    {
        let disp = extract_field_display(first, "name").unwrap_or_else(|| sys_id.clone());
        return Ok((disp, sys_id));
    }

    Err(SncfrError::Validation {
        message: format!("Could not resolve user reference '{trimmed}' in sys_user"),
        valid_choices: vec![],
        remediation: Some(
            "Pass `@me`, `none`, a valid ServiceNow username/email, or a 32-character user `sys_id`."
                .to_string(),
        ),
    })
}

pub async fn resolve_group_reference(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<(String, String), SncfrError> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("unassigned")
    {
        return Ok(("(unassigned)".to_string(), String::new()));
    }
    if is_sys_id(trimmed) {
        return Ok((trimmed.to_string(), trimmed.to_string()));
    }

    // Check cached `@my-groups` first
    if let Ok(Some(identity)) = cache.read_identity()
        && let Some(found) = identity
            .groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(trimmed))
    {
        return Ok((found.name.clone(), found.sys_id.clone()));
    }

    let trimmed = crate::untrusted::query_value(trimmed)?;
    let q = format!("name={trimmed}");
    let resp: Value = client
        .get_json(
            "/api/now/table/sys_user_group",
            &[
                ("sysparm_query", q.as_str()),
                ("sysparm_limit", "2"),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "sys_id,name"),
            ],
        )
        .await?;

    if let Some(first) = resp
        .get("result")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        && let Some(sys_id) = extract_field_value(first, "sys_id")
    {
        let disp = extract_field_display(first, "name").unwrap_or_else(|| sys_id.clone());
        return Ok((disp, sys_id));
    }

    Err(SncfrError::Validation {
        message: format!("Could not resolve assignment group '{trimmed}' in sys_user_group"),
        valid_choices: vec![],
        remediation: Some(
            "Pass an exact ServiceNow group name or a 32-character group `sys_id`.".to_string(),
        ),
    })
}

fn resolve_message_body(args: &CommentArgs) -> Result<String, SncfrError> {
    if let Some(path) = &args.file {
        let content = fs::read_to_string(path).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to read message file '{}': {e}", path.display()),
            remediation: None,
        })?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(SncfrError::InvalidArgs {
                message: format!("Message file '{}' is empty", path.display()),
                remediation: None,
            });
        }
        return Ok(trimmed.to_string());
    }
    if let Some(msg) = &args.message
        && !msg.trim().is_empty()
    {
        return Ok(msg.trim().to_string());
    }
    Err(SncfrError::InvalidArgs {
        message: "Comment/note message body cannot be empty".to_string(),
        remediation: Some("Pass `<MESSAGE>` or `--file <path>`.".to_string()),
    })
}

pub fn parse_key_value_pair(raw: &str) -> Result<(String, String), SncfrError> {
    let Some((k, v)) = raw.split_once('=') else {
        return Err(SncfrError::InvalidArgs {
            message: format!("Invalid FIELD=VALUE pair '{raw}' (missing `=`)"),
            remediation: Some("Use `--set field_name=value` syntax.".to_string()),
        });
    };
    let key = k.trim();
    if key.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: format!("Field name cannot be empty in '{raw}'"),
            remediation: None,
        });
    }
    Ok((key.to_string(), v.trim().to_string()))
}

/// Quotes a CLI argument for safe copy-pasting in POSIX shells.
pub fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@' | '=')
        })
    {
        return arg.to_string();
    }
    if !arg.contains('\'') {
        format!("'{arg}'")
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn build_update_commit_command(ticket_number: &str, args: &UpdateArgs) -> String {
    let mut parts = vec![
        "sncfr".to_string(),
        "update".to_string(),
        shell_quote(ticket_number),
    ];
    for (flag, opt_val) in [
        ("--state", &args.state),
        ("--priority", &args.priority),
        ("--urgency", &args.urgency),
        ("--impact", &args.impact),
        ("--assign-to", &args.assign_to),
        ("--group", &args.group),
        ("--short-description", &args.short_description),
        ("--description", &args.description),
        ("--close-code", &args.close_code),
        ("--close-notes", &args.close_notes),
        ("--note", &args.note),
        ("--comment", &args.comment),
    ] {
        if let Some(val) = opt_val {
            parts.push(flag.to_string());
            parts.push(shell_quote(val));
        }
    }
    for kv in &args.set_fields {
        parts.push("--set".to_string());
        parts.push(shell_quote(kv));
    }
    parts.push("--write".to_string());
    parts.join(" ")
}

fn build_create_commit_command(table: &str, args: &CreateArgs) -> String {
    let mut parts = vec![
        "sncfr".to_string(),
        "create".to_string(),
        shell_quote(table),
        "--short-description".to_string(),
        shell_quote(&args.short_description),
    ];
    for (flag, opt_val) in [
        ("--description", &args.description),
        ("--priority", &args.priority),
        ("--urgency", &args.urgency),
        ("--impact", &args.impact),
        ("--assign-to", &args.assign_to),
        ("--group", &args.group),
        ("--caller", &args.caller),
    ] {
        if let Some(val) = opt_val {
            parts.push(flag.to_string());
            parts.push(shell_quote(val));
        }
    }
    for kv in &args.set_fields {
        parts.push("--set".to_string());
        parts.push(shell_quote(kv));
    }
    parts.push("--write".to_string());
    parts.join(" ")
}

fn build_attach_commit_command(ticket_number: &str, args: &AttachArgs) -> String {
    let mut parts = vec![
        "sncfr".to_string(),
        "attach".to_string(),
        shell_quote(ticket_number),
    ];
    for path in &args.files {
        parts.push(shell_quote(&path.display().to_string()));
    }
    parts.push("--write".to_string());
    parts.join(" ")
}

fn guess_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "log" | "md") => "text/plain",
        Some("json") => "application/json",
        Some("yaml" | "yml") => "application/x-yaml",
        Some("csv") => "text/csv",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

/// Formats a [`MutationReport`] (Dry-Run Preview or Committed Write) according to `format`.
pub fn format_mutation_report(report: &MutationReport, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(report).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(report).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            let badge = if report.mode == "dry_run" {
                "DRY-RUN PREVIEW (No changes written to ServiceNow)"
            } else {
                "COMMITTED WRITE"
            };
            out.push_str(&format!(
                "# {} — `{}` on `{}`\n\n",
                badge,
                report.operation,
                report.ticket.as_deref().unwrap_or(&report.table)
            ));
            out.push_str(&format!("- **Table**: `{}`\n", report.table));
            if let Some(sys_id) = &report.sys_id {
                out.push_str(&format!("- **sys_id**: `{sys_id}`\n"));
            }
            if let Some(url) = &report.ui_url {
                out.push_str(&format!("- **URL**: {url}\n"));
            }
            out.push('\n');

            if !report.diffs.is_empty() {
                out.push_str("## Field Changes (Before -> After)\n\n");
                out.push_str(
                    "| Field | Before | After (label) | Sends (value) | Source | Status |\n",
                );
                out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
                // Before values come from the instance and after values from the caller (often
                // an agent): neither may add table cells, rows, or escapes (NA-9).
                for d in &report.diffs {
                    let before = d.before_display.as_deref().unwrap_or("(new/append)");
                    let status = d.status.as_deref().unwrap_or("—");
                    let status = if status.starts_with("UNVERIFIABLE") {
                        format!("**{status}**")
                    } else {
                        status.to_string()
                    };
                    out.push_str(&format!(
                        "| `{}` | {} | **{}** | `{}` | {} | {} |\n",
                        crate::untrusted::inline(&d.field),
                        crate::untrusted::inline(before),
                        crate::untrusted::inline(&d.after_display),
                        crate::untrusted::inline(&d.after_value),
                        d.source.as_deref().unwrap_or("—"),
                        status
                    ));
                }
                out.push('\n');
            }

            if !report.attachments.is_empty() {
                out.push_str("## Attachments\n\n");
                for att in &report.attachments {
                    out.push_str(&format!(
                        "- **`{}`** ({} bytes, `{}`){}\n",
                        att.file_name,
                        att.size_bytes,
                        att.content_type,
                        att.attachment_sys_id
                            .as_ref()
                            .map(|id| format!(" -> uploaded `sys_id={id}`"))
                            .unwrap_or_default()
                    ));
                }
                out.push('\n');
            }

            if let Some(cmd) = &report.commit_command {
                out.push_str(&format!(
                    "> To commit this change to ServiceNow, re-run with `--write`:\n> `{cmd}`\n"
                ));
            }
            out
        }
        ResolvedOutputFormat::TerminalDossier | ResolvedOutputFormat::Table => {
            let mut out = String::new();
            let header = if report.mode == "dry_run" {
                "[DRY-RUN PREVIEW — Read-Only Validation Passed; No Changes Written]"
            } else {
                "[COMMITTED WRITE — Changes Saved to ServiceNow]"
            };
            out.push_str(&format!("{header}\n"));
            let target_label = match (&report.ticket, &report.ui_url) {
                (Some(t), Some(url)) => osc8_link(url, t),
                (Some(t), None) => t.clone(),
                (None, _) => "(new record)".to_string(),
            };
            out.push_str(&format!(
                "Operation: {}\nTarget:    {} (table: {})\n",
                report.operation, target_label, report.table
            ));
            if let Some(url) = &report.ui_url {
                out.push_str(&format!("URL:       {}\n", osc8_link(url, url)));
            }

            if !report.diffs.is_empty() {
                out.push('\n');
                let mut table = Table::new();
                let width = table.width().unwrap_or(120).max(120);
                table
                    .load_preset(UTF8_FULL_CONDENSED)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_width(width)
                    .set_header(vec![
                        "FIELD", "BEFORE", "AFTER", "SENDS", "SOURCE", "STATUS",
                    ]);
                // No instance- or caller-supplied text reaches the terminal with control or
                // escape sequences, which could rewrite or hide lines of the preview (NA-9).
                for d in &report.diffs {
                    table.add_row(vec![
                        crate::untrusted::clean(&d.field),
                        crate::untrusted::clean(d.before_display.as_deref().unwrap_or("(none)")),
                        crate::untrusted::clean(&d.after_display),
                        crate::untrusted::clean(&d.after_value),
                        d.source.clone().unwrap_or_else(|| "—".to_string()),
                        d.status.clone().unwrap_or_else(|| "—".to_string()),
                    ]);
                }
                out.push_str(&table.to_string());
                out.push('\n');
            }

            if !report.attachments.is_empty() {
                out.push_str("\nAttachments:\n");
                for att in &report.attachments {
                    out.push_str(&format!(
                        "  - {} ({} bytes, {}){}\n",
                        att.file_name,
                        att.size_bytes,
                        att.content_type,
                        att.attachment_sys_id
                            .as_ref()
                            .map(|id| format!(" [sys_id={id}]"))
                            .unwrap_or_default()
                    ));
                }
            }

            if let Some(cmd) = &report.commit_command {
                out.push_str(&format!(
                    "\nTo commit this change, pass `--write`:\n  {cmd}\n"
                ));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::client::ClientAuth;
    use clap::Parser;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn dry_run_update_validates_choices_and_references_without_sending_patch() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "inc_42", "display_value": "inc_42" },
                    "number": { "value": "INC0010042", "display_value": "INC0010042" },
                    "state": { "value": "1", "display_value": "New" }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_dictionary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_choice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "name": { "value": "incident", "display_value": "Incident" },
                    "element": { "value": "state", "display_value": "state" },
                    "label": { "value": "In Progress", "display_value": "In Progress" },
                    "value": { "value": "2", "display_value": "2" },
                    "sequence": { "value": "2", "display_value": "2" }
                }]
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

        let args = UpdateArgs {
            ticket: "INC0010042".to_string(),
            state: Some("In Progress".to_string()),
            priority: None,
            urgency: None,
            impact: None,
            assign_to: None,
            group: None,
            short_description: None,
            description: None,
            close_code: None,
            close_notes: None,
            note: Some("Investigating now".to_string()),
            comment: None,
            set_fields: vec![],
            write: false,
        };

        let report = execute_update(client.clone(), &cache, &args, None)
            .await
            .expect("dry-run update");
        assert_eq!(report.mode, "dry_run");
        assert_eq!(report.diffs.len(), 2);
        assert_eq!(report.diffs[0].before_display.as_deref(), Some("New"));
        assert_eq!(report.diffs[0].after_display, "In Progress");
        assert_eq!(report.diffs[0].after_value, "2");
        assert_eq!(
            report.commit_command.as_deref(),
            Some(
                "sncfr update INC0010042 --state 'In Progress' --note 'Investigating now' --write"
            )
        );

        // Now execute with `--write` (`WritePermit`)
        Mock::given(method("PATCH"))
            .and(path("/api/now/table/incident/inc_42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": { "sys_id": "inc_42" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let write_cli = Cli::try_parse_from([
            "sncfr",
            "update",
            "INC0010042",
            "--state",
            "In Progress",
            "--write",
        ])
        .expect("parse write cli");
        let permit = WritePermit::issue(&write_cli, None)
            .expect("issue")
            .expect("permit present");

        let committed = execute_update(client, &cache, &args, Some(permit))
            .await
            .expect("committed update");
        assert_eq!(committed.mode, "committed");
        assert!(committed.commit_command.is_none());
    }

    #[test]
    fn previews_strip_terminal_escapes_and_markdown_structure_from_values() {
        // CT-45b: an instance "Before" value tries to erase the line above and set the clipboard.
        let report = MutationReport {
            mode: "dry_run".to_string(),
            operation: "update".to_string(),
            ticket: Some("INC0012345".to_string()),
            table: "incident".to_string(),
            sys_id: None,
            ui_url: None,
            diffs: vec![FieldDiff {
                field: "short_description".to_string(),
                before_display: Some("ok\u{1b}[1A\u{1b}[2K\u{1b}]52;c;Zm9v\u{7}".to_string()),
                before_value: None,
                after_display: "new | forged | cell\n## heading".to_string(),
                after_value: "x".to_string(),
                ..Default::default()
            }],
            attachments: vec![],
            commit_command: None,
        };
        for format in [
            ResolvedOutputFormat::Table,
            ResolvedOutputFormat::TerminalDossier,
        ] {
            let out = format_mutation_report(&report, format);
            assert!(!out.contains("\u{1b}[1A"), "{out:?}");
            assert!(!out.contains("\u{1b}]52"), "{out:?}");
            assert!(!out.contains('\u{7}'), "{out:?}");
        }
        let md = format_mutation_report(&report, ResolvedOutputFormat::Md);
        assert!(!md.contains('\u{1b}'));
        assert!(!md.contains("\n## heading"));
        assert!(md.contains("new \\| forged \\| cell"), "{md}");
    }
}
