use crate::cache::InstanceCache;
use crate::cli::{AttachArgs, CommentArgs, CreateArgs, UpdateArgs};
use crate::client::write_gate::{ResolvedField, Target, VerifiedMutation, WriteOutcome};
use crate::client::{
    ReadOnlyClient, WritePermit, extract_field_display, extract_field_pair, extract_field_value,
};
use crate::error::SncfrError;
use crate::output::{ResolvedOutputFormat, osc8_link};
use crate::resolve::{load_or_sync_prefixes, resolve_table_name, resolve_ticket};
use crate::resolve_value::{
    ResolveCtx, ResolvedValue, discover_in_use, resolve_choice, resolve_field,
};
use crate::schema::load_or_sync_table_schema;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

pub use crate::client::write_gate::UnverifiableField;

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
            unverifiable: UnverifiableField::from_resolved(field, input, resolved),
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationReport {
    /// `"dry_run"`, `"blocked"` (`--write` refused: unverifiable values), or `"committed"`.
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
    /// Values that could not be verified and were not allowed: the command exits 8 (SAFE-3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverifiable_fields: Vec<UnverifiableField>,
    /// Unverifiable fields named in `--allow-unverified` (sent exactly as typed) (SAFE-4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_unverified: Vec<String>,
    /// `--allow-unverified` names that weren't unverifiable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_unverified_unused: Vec<String>,
    /// Fields the instance returned with a different value than sent: the command exits 9.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_applied: Vec<crate::client::write_gate::NotApplied>,
    /// Fields absent from the write response (not confirmed, not refuted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed: Vec<String>,
    /// Merged Instance Pack headline (`<name> <version> · <status> · sha256:…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
    /// The post-order fill (CAT-3): a second diff block for the RITM the order creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_ritm: Option<FollowUpBlock>,
    /// Requested items created by a catalog order (CAT-2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<OrderedItem>,
    /// Non-fatal notes (e.g. RITM polling timed out); the command still succeeded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Writes to a record that a write earlier in the same invocation creates (CAT-3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowUpBlock {
    /// `<RITM created by this order>` until bound, then the RITM number.
    pub target: String,
    pub diffs: Vec<FieldDiff>,
}

/// One `sc_req_item` created by a catalog order (CAT-2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedItem {
    pub sys_id: String,
    pub number: String,
    pub cat_item: String,
}

/// What the write gate did for one invocation.
pub(crate) struct GateRun {
    /// `dry_run`, `blocked`, or `committed`.
    pub mode: &'static str,
    pub outcomes: Vec<WriteOutcome>,
    pub blocking: Vec<UnverifiableField>,
    pub allowed: Vec<String>,
    pub unused: Vec<String>,
    /// The follow-up stage's result, for committed runs.
    pub binding: Option<Binding>,
}

/// Runs prepared mutations through the gate: a dry-run only checks them; `--write` authorizes
/// all of them before sending the first (NA-2), then sends each.
/// What the follow-up stage learned after the first write (CAT-2/3): the record a deferred
/// write is bound to (none: deferred writes are skipped), plus items and warnings to report.
#[derive(Debug, Clone, Default)]
pub(crate) struct Binding {
    pub sys_id: Option<String>,
    pub items: Vec<OrderedItem>,
    pub warnings: Vec<String>,
}

/// Checks every mutation of the invocation, deferred ones included, before anything is sent
/// (NA-2). Then sends the immediate ones, asks `bind` (given the first write's outcome) which
/// record the deferred ones target, and sends those bound to it.
pub(crate) async fn run_gate_staged<F, Fut>(
    client: ReadOnlyClient,
    permit: Option<WritePermit>,
    mutations: Vec<VerifiedMutation>,
    bind: F,
) -> Result<GateRun, SncfrError>
where
    F: FnOnce(Option<&WriteOutcome>) -> Fut,
    Fut: std::future::Future<Output = Binding>,
{
    let allow = crate::client::write_gate::allow_list();
    let all: Vec<UnverifiableField> = mutations
        .iter()
        .flat_map(|m| m.unverifiable().to_vec())
        .collect();
    let blocking: Vec<UnverifiableField> =
        mutations.iter().flat_map(|m| m.blocking(allow)).collect();
    let allowed: Vec<String> = all
        .iter()
        .filter(|u| allow.contains(&u.field))
        .map(|u| u.field.clone())
        .collect();
    let unused: Vec<String> = allow
        .names()
        .filter(|n| !all.iter().any(|u| u.field.eq_ignore_ascii_case(n)))
        .cloned()
        .collect();
    let Some(permit) = permit else {
        return Ok(GateRun {
            mode: "dry_run",
            outcomes: Vec::new(),
            blocking,
            allowed,
            unused,
            binding: None,
        });
    };
    if !blocking.is_empty() {
        return Ok(GateRun {
            mode: "blocked",
            outcomes: Vec::new(),
            blocking,
            allowed,
            unused,
            binding: None,
        });
    }
    let mutating = client.into_mutating(permit);
    let payloads = mutating.authorize(mutations, allow)?;
    let (now, later): (Vec<_>, Vec<_>) = payloads.into_iter().partition(|p| !p.is_deferred());
    let mut outcomes = Vec::with_capacity(now.len() + later.len());
    for p in now {
        outcomes.push(mutating.send(p).await?);
    }
    let binding = bind(outcomes.first()).await;
    if let Some(sys_id) = &binding.sys_id {
        for p in later {
            outcomes.push(mutating.send(p.bind(sys_id)?).await?);
        }
    }
    Ok(GateRun {
        mode: "committed",
        outcomes,
        blocking,
        allowed,
        unused,
        binding: Some(binding),
    })
}

/// [`run_gate_staged`] for invocations without deferred writes.
pub(crate) async fn run_gate(
    client: ReadOnlyClient,
    permit: Option<WritePermit>,
    mutations: Vec<VerifiedMutation>,
) -> Result<GateRun, SncfrError> {
    run_gate_staged(client, permit, mutations, |_| async { Binding::default() }).await
}

impl GateRun {
    /// Fills the gate results into `report` and marks allowed rows in its diffs.
    pub(crate) fn fill(&self, report: &mut MutationReport) {
        report.mode = self.mode.to_string();
        if let Some(b) = &self.binding {
            report.items.extend(b.items.iter().cloned());
            report.warnings.extend(b.warnings.iter().cloned());
        }
        report.unverifiable_fields.clone_from(&self.blocking);
        report.allowed_unverified.clone_from(&self.allowed);
        report.allowed_unverified_unused.clone_from(&self.unused);
        report.not_applied = self
            .outcomes
            .iter()
            .flat_map(|o| o.not_applied.clone())
            .collect();
        report.unconfirmed = self
            .outcomes
            .iter()
            .flat_map(|o| o.unconfirmed.clone())
            .collect();
        report.pack = Some(crate::pack::active().summary().headline());
        for d in &mut report.diffs {
            if let Some(u) = &d.unverifiable
                && self.allowed.iter().any(|a| a == &d.field)
            {
                d.status = Some(format!("allowed unverified ({})", u.reason));
            }
        }
        if self.mode == "committed" {
            report.commit_command = None;
        }
    }

    /// The first write's response record (`result`), when there was one.
    pub(crate) fn first_record(&self) -> Option<&Value> {
        self.outcomes
            .first()
            .map(|o| o.response.get("result").unwrap_or(&o.response))
    }
}

/// The exit status a report implies: 8 when values were left unverifiable, 9 when the instance
/// silently didn't apply fields, otherwise success. `main` prints the report either way.
pub fn report_error(report: &MutationReport) -> Option<SncfrError> {
    if !report.unverifiable_fields.is_empty() {
        return Some(SncfrError::Unverifiable {
            fields: report.unverifiable_fields.clone(),
        });
    }
    if !report.not_applied.is_empty() {
        return Some(SncfrError::WriteNotApplied {
            not_applied: report.not_applied.clone(),
        });
    }
    None
}

/// The pack's agent write marker for this invocation (SAFE-8), installed once by `main` when the
/// invocation is non-interactive. `None` means comments and notes are sent as typed.
static JOURNAL_MARKER: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Whether this invocation counts as an agent's (SAFE-8): `--no-interactive`, `SNCFR_AGENT=1`, a
/// non-TTY stdin, or profile `agent_marker = "always"`. stdout piping alone does not count.
pub fn agent_invocation(
    no_interactive: bool,
    agent_env: Option<&str>,
    stdin_is_tty: bool,
    profile: crate::config::AgentMarkerMode,
) -> bool {
    no_interactive
        || agent_env.is_some_and(|v| v.trim() == "1")
        || !stdin_is_tty
        || profile == crate::config::AgentMarkerMode::Always
}

/// Installs the marker applied to every `comments` / `work_notes` payload of this invocation.
pub fn install_journal_marker(marker: Option<String>) -> bool {
    JOURNAL_MARKER.set(marker).is_ok()
}

fn journal_marker() -> Option<&'static str> {
    JOURNAL_MARKER.get().and_then(Option::as_deref)
}

/// A `comments` / `work_notes` payload: `[code]` (rendered as HTML by ServiceNow) needs
/// `allow_code_tag`, and the marker, when set, is prepended as `"<marker> "` (NA-12). Returns the
/// payload and whether it was marked.
pub fn journal_payload(
    body: &str,
    marker: Option<&str>,
    allow_code_tag: bool,
) -> Result<(String, bool), SncfrError> {
    if body.to_ascii_lowercase().contains("[code]") {
        if !allow_code_tag {
            return Err(SncfrError::InvalidArgs {
                message: "The body contains `[code]`, which ServiceNow renders as raw HTML"
                    .to_string(),
                remediation: Some(
                    "Remove the `[code]` tag, or pass --allow-code-tag if the HTML is intended."
                        .to_string(),
                ),
            });
        }
        eprintln!("warning: the body contains `[code]`; ServiceNow will render it as raw HTML");
    }
    match marker.map(str::trim).filter(|m| !m.is_empty()) {
        Some(m) if !body.starts_with(&format!("{m} ")) => Ok((format!("{m} {body}"), true)),
        Some(_) => Ok((body.to_string(), true)),
        None => Ok((body.to_string(), false)),
    }
}

/// [`journal_payload`] with this invocation's marker, plus the preview `Source` label.
pub(crate) fn marked_journal(
    body: &str,
    allow_code_tag: bool,
) -> Result<(String, &'static str), SncfrError> {
    let (text, marked) = journal_payload(body, journal_marker(), allow_code_tag)?;
    Ok((text, if marked { "input + marker" } else { "input" }))
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
    let typed_body = resolve_message_body(args)?;
    let (body_text, source) = marked_journal(&typed_body, args.allow_code_tag)?;
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
        source: Some(source.to_string()),
        status: Some("n/a (free text)".to_string()),
        ..Default::default()
    };
    let fields: Vec<ResolvedField> = vec![(
        field_name.to_string(),
        body_text.clone(),
        ResolvedValue::text(&body_text),
    )];
    let mutation = VerifiedMutation::record(
        Target::patch_record(&resolved.table, &resolved.sys_id)?,
        &fields,
    );

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
            shell_quote(&typed_body)
        )
    };
    let gate = run_gate(client, permit, vec![mutation]).await?;
    let mut report = MutationReport {
        operation: op_name.to_string(),
        ticket: Some(resolved.number),
        table: resolved.table,
        sys_id: Some(resolved.sys_id),
        ui_url: Some(ui_url),
        diffs: vec![diff],
        commit_command: Some(commit_cmd),
        ..Default::default()
    };
    gate.fill(&mut report);
    Ok(report)
}

/// The fields a mutation sets through choice flags or `--set` (malformed pairs are skipped here
/// and rejected where they are parsed), for in-use discovery before resolution.
fn mutation_fields(choice_flags: &[(&str, &Option<String>)], set_fields: &[String]) -> Vec<String> {
    choice_flags
        .iter()
        .filter(|(_, v)| v.is_some())
        .map(|(f, _)| (*f).to_string())
        .chain(
            set_fields
                .iter()
                .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string())),
        )
        .collect()
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

    let probe = ResolveCtx {
        pack: crate::pack::active(),
        table: &resolved.table,
        schema: &schema,
        sample: Some(&resolved.record),
        discovered: None,
    };
    let wanted = mutation_fields(
        &[
            ("state", &args.state),
            ("priority", &args.priority),
            ("urgency", &args.urgency),
            ("impact", &args.impact),
            ("close_code", &args.close_code),
        ],
        &args.set_fields,
    );
    let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
    let discovered = discover_in_use(&client, cache, &probe, &wanted).await?;
    let ctx = ResolveCtx {
        discovered: Some(&discovered),
        ..probe
    };
    let mut diffs = Vec::new();
    let mut fields: Vec<ResolvedField> = Vec::new();

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
            fields.push((field.to_string(), input_val.clone(), value));
        }
    }

    // 2. User & Group Reference fields (`assigned_to`, `assignment_group`)
    if let Some(assign_to) = &args.assign_to {
        let (after_disp, after_val, ref_source) =
            resolve_user_reference(&client, cache, assign_to).await?;
        let before = extract_field_pair(&resolved.record, "assigned_to");
        diffs.push(FieldDiff {
            field: "assigned_to".to_string(),
            before_display: before.as_ref().map(|b| b.0.clone()),
            before_value: before.as_ref().map(|b| b.1.clone()),
            after_display: after_disp.clone(),
            after_value: after_val.clone(),
            source: Some(ref_source.clone()),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        fields.push((
            "assigned_to".to_string(),
            assign_to.clone(),
            ResolvedValue::verified(after_val, Some(after_disp), None),
        ));
    }

    if let Some(group) = &args.group {
        let (after_disp, after_val, ref_source) =
            resolve_group_reference(&client, cache, group).await?;
        let before = extract_field_pair(&resolved.record, "assignment_group");
        diffs.push(FieldDiff {
            field: "assignment_group".to_string(),
            before_display: before.as_ref().map(|b| b.0.clone()),
            before_value: before.as_ref().map(|b| b.1.clone()),
            after_display: after_disp.clone(),
            after_value: after_val.clone(),
            source: Some(ref_source.clone()),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        fields.push((
            "assignment_group".to_string(),
            group.clone(),
            ResolvedValue::verified(after_val, Some(after_disp), None),
        ));
    }

    // 3. Text fields (`short_description`, `description`, `close_notes`, `work_notes`, `comments`)
    for (field, opt_val) in [
        ("short_description", &args.short_description),
        ("description", &args.description),
        ("close_notes", &args.close_notes),
        ("work_notes", &args.note),
        ("comments", &args.comment),
    ] {
        if let Some(typed) = opt_val {
            let journal = field == "work_notes" || field == "comments";
            let (val, source) = if journal {
                marked_journal(typed, args.allow_code_tag)?
            } else {
                (typed.clone(), "input")
            };
            let before = if journal {
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
                source: Some(source.to_string()),
                status: Some("n/a (free text)".to_string()),
                ..Default::default()
            });
            fields.push((field.to_string(), val.clone(), ResolvedValue::text(&val)));
        }
    }

    // 4. Arbitrary `--set field=value` pairs
    for kv in &args.set_fields {
        let (k, v) = parse_key_value_pair(kv)?;
        let value = resolve_field(&ctx, &k, &v)?;
        let before = extract_field_pair(&resolved.record, &k);
        diffs.push(FieldDiff::from_resolved(&k, before, &v, &value));
        fields.push((k, v, value));
    }

    if fields.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "No field updates were specified for `sncfr update`".to_string(),
            remediation: Some(
                "Pass at least one field flag (e.g., `--state`, `--assign-to`, `--priority`, `--set key=value`)."
                    .to_string(),
            ),
        });
    }

    let mutation = VerifiedMutation::record(
        Target::patch_record(&resolved.table, &resolved.sys_id)?,
        &fields,
    );
    let gate = run_gate(client, permit, vec![mutation]).await?;
    let mut report = MutationReport {
        operation: "update".to_string(),
        ticket: Some(resolved.number.clone()),
        table: resolved.table,
        sys_id: Some(resolved.sys_id),
        ui_url: Some(ui_url),
        diffs,
        commit_command: Some(build_update_commit_command(&resolved.number, args)),
        ..Default::default()
    };
    gate.fill(&mut report);
    Ok(report)
}

pub async fn execute_create(
    client: ReadOnlyClient,
    cache: &InstanceCache,
    args: &CreateArgs,
    permit: Option<WritePermit>,
) -> Result<MutationReport, SncfrError> {
    let prefixes = load_or_sync_prefixes(&client, cache, false).await?;
    let table = resolve_table_name(&args.table_or_prefix, &prefixes);
    let schema = load_or_sync_table_schema(&client, cache, &table, false).await?;
    let probe = ResolveCtx {
        pack: crate::pack::active(),
        table: &table,
        schema: &schema,
        sample: None,
        discovered: None,
    };
    let wanted = mutation_fields(
        &[
            ("priority", &args.priority),
            ("urgency", &args.urgency),
            ("impact", &args.impact),
        ],
        &args.set_fields,
    );
    let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
    let discovered = discover_in_use(&client, cache, &probe, &wanted).await?;
    let ctx = ResolveCtx {
        discovered: Some(&discovered),
        ..probe
    };

    let mut diffs = Vec::new();
    let mut fields: Vec<ResolvedField> = Vec::new();

    diffs.push(FieldDiff {
        field: "short_description".to_string(),
        before_display: None,
        before_value: None,
        after_display: args.short_description.clone(),
        after_value: args.short_description.clone(),
        source: Some("input".to_string()),
        status: Some("n/a (free text)".to_string()),
        ..Default::default()
    });
    fields.push((
        "short_description".to_string(),
        args.short_description.clone(),
        ResolvedValue::text(&args.short_description),
    ));

    if let Some(desc) = &args.description {
        diffs.push(FieldDiff {
            field: "description".to_string(),
            before_display: None,
            before_value: None,
            after_display: desc.clone(),
            after_value: desc.clone(),
            source: Some("input".to_string()),
            status: Some("n/a (free text)".to_string()),
            ..Default::default()
        });
        fields.push((
            "description".to_string(),
            desc.clone(),
            ResolvedValue::text(desc),
        ));
    }

    for (field, opt_val) in [
        ("priority", &args.priority),
        ("urgency", &args.urgency),
        ("impact", &args.impact),
    ] {
        if let Some(input_val) = opt_val {
            let value = resolve_choice(&ctx, field, input_val)?;
            diffs.push(FieldDiff::from_resolved(field, None, input_val, &value));
            fields.push((field.to_string(), input_val.clone(), value));
        }
    }

    if let Some(assign_to) = &args.assign_to {
        let (after_disp, after_val, ref_source) =
            resolve_user_reference(&client, cache, assign_to).await?;
        diffs.push(FieldDiff {
            field: "assigned_to".to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp.clone(),
            after_value: after_val.clone(),
            source: Some(ref_source.clone()),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        fields.push((
            "assigned_to".to_string(),
            assign_to.clone(),
            ResolvedValue::verified(after_val, Some(after_disp), None),
        ));
    }

    if let Some(group) = &args.group {
        let (after_disp, after_val, ref_source) =
            resolve_group_reference(&client, cache, group).await?;
        diffs.push(FieldDiff {
            field: "assignment_group".to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp.clone(),
            after_value: after_val.clone(),
            source: Some(ref_source.clone()),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        fields.push((
            "assignment_group".to_string(),
            group.clone(),
            ResolvedValue::verified(after_val, Some(after_disp), None),
        ));
    }

    if let Some(caller) = &args.caller {
        let (after_disp, after_val, ref_source) =
            resolve_user_reference(&client, cache, caller).await?;
        let caller_field = crate::pack::active().caller_field(&table);
        diffs.push(FieldDiff {
            field: caller_field.to_string(),
            before_display: None,
            before_value: None,
            after_display: after_disp.clone(),
            after_value: after_val.clone(),
            source: Some(ref_source.clone()),
            status: Some("verified".to_string()),
            ..Default::default()
        });
        fields.push((
            caller_field.to_string(),
            caller.clone(),
            ResolvedValue::verified(after_val, Some(after_disp), None),
        ));
    }

    for kv in &args.set_fields {
        let (k, v) = parse_key_value_pair(kv)?;
        let value = resolve_field(&ctx, &k, &v)?;
        diffs.push(FieldDiff::from_resolved(&k, None, &v, &value));
        fields.push((k, v, value));
    }

    let base_url = client.base_url().as_str().trim_end_matches('/').to_string();

    let mutation = VerifiedMutation::record(Target::post_table(&table)?, &fields);
    let gate = run_gate(client, permit, vec![mutation]).await?;
    let created = gate.first_record();
    let sys_id = created.and_then(|r| extract_field_value(r, "sys_id"));
    let number = created.and_then(|r| extract_field_display(r, "number"));
    let ui_url = sys_id
        .as_ref()
        .map(|id| format!("{base_url}/nav_to.do?uri={table}.do?sys_id={id}"));
    let mut report = MutationReport {
        operation: "create".to_string(),
        ticket: number,
        table: table.clone(),
        sys_id,
        ui_url,
        diffs,
        commit_command: Some(build_create_commit_command(&table, args)),
        ..Default::default()
    };
    gate.fill(&mut report);
    Ok(report)
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

    let mut items = Vec::with_capacity(prepared_files.len());
    let mut mutations = Vec::with_capacity(prepared_files.len());
    for (file_name, local_path, content_type, bytes) in prepared_files {
        items.push(AttachmentMutationItem {
            file_name: file_name.clone(),
            local_path,
            content_type: content_type.clone(),
            size_bytes: bytes.len(),
            attachment_sys_id: None,
        });
        mutations.push(VerifiedMutation::attachment(
            &resolved.table,
            &resolved.sys_id,
            &file_name,
            &content_type,
            bytes,
        )?);
    }
    let gate = run_gate(client, permit, mutations).await?;
    for (item, outcome) in items.iter_mut().zip(&gate.outcomes) {
        item.attachment_sys_id = outcome
            .response
            .get("result")
            .and_then(|r| extract_field_value(r, "sys_id"));
    }
    let mut report = MutationReport {
        operation: "attach".to_string(),
        ticket: Some(resolved.number.clone()),
        table: resolved.table,
        sys_id: Some(resolved.sys_id),
        ui_url: Some(ui_url),
        attachments: items,
        commit_command: Some(build_attach_commit_command(&resolved.number, args)),
        ..Default::default()
    };
    gate.fill(&mut report);
    Ok(report)
}

/// Resolves a user reference; returns `(display, sys_id, source label)` (see [`crate::references`]).
pub async fn resolve_user_reference(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<(String, String, String), SncfrError> {
    let m = crate::references::resolve_user(client, cache, input).await?;
    Ok((m.name.clone(), m.sys_id.clone(), m.source_label("user")))
}

/// Resolves a group reference; returns `(display, sys_id, source label)` (see [`crate::references`]).
pub async fn resolve_group_reference(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<(String, String, String), SncfrError> {
    let m = crate::references::resolve_group(client, cache, input).await?;
    let mut source = m.source_label("group");
    if let Some(s) = &m.suggestion
        && s != &m.name
    {
        source.push_str(&format!("; note: pack suggests \"{s}\""));
    }
    Ok((m.name.clone(), m.sys_id.clone(), source))
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

            out.push_str(&gate_notes(report, false));
            if let Some(cmd) = &report.commit_command {
                if report.unverifiable_fields.is_empty() {
                    out.push_str(&format!(
                        "> To commit this change to ServiceNow, re-run with `--write`:\n> `{cmd}`\n"
                    ));
                } else {
                    out.push_str(&format!("> Commit (blocked until resolved): `{cmd}`\n"));
                }
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

            out.push_str(&gate_notes(report, true));
            if let Some(cmd) = &report.commit_command {
                if report.unverifiable_fields.is_empty() {
                    out.push_str(&format!(
                        "\nTo commit this change, pass `--write`:\n  {cmd}\n"
                    ));
                } else {
                    out.push_str(&format!("\nCommit (blocked until resolved):\n  {cmd}\n"));
                }
            }
            out
        }
    }
}

/// The pack footer, the "not written" block for unverifiable values, and post-write findings.
fn gate_notes(report: &MutationReport, terminal: bool) -> String {
    let clean = |s: &str| {
        if terminal {
            crate::untrusted::clean(s)
        } else {
            crate::untrusted::inline(s)
        }
    };
    let mut out = String::new();
    if let Some(pack) = &report.pack {
        out.push_str(&format!("\nPack: {}\n", clean(pack)));
    }
    if let Some(block) = &report.fill_ritm {
        out.push_str(&format!(
            "\nThen on {} (--fill-ritm, checked with the order):\n",
            clean(&block.target)
        ));
        for d in &block.diffs {
            out.push_str(&format!(
                "  {} → {} [{} · {}]\n",
                clean(&d.field),
                clean(&d.after_display),
                d.source.as_deref().unwrap_or("none"),
                d.status.as_deref().unwrap_or("")
            ));
        }
    }
    if !report.items.is_empty() {
        out.push_str("\nRequested items:\n");
        for i in &report.items {
            out.push_str(&format!(
                "  {} (sys_id {})\n",
                clean(&i.number),
                clean(&i.sys_id)
            ));
        }
    }
    for w in &report.warnings {
        out.push_str(&format!("\n⚠ {}\n", clean(w)));
    }
    if !report.unverifiable_fields.is_empty() {
        out.push_str(&format!(
            "\n⚠ Not written: {} field{} could not be verified (exit 8).\n",
            report.unverifiable_fields.len(),
            if report.unverifiable_fields.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        for u in &report.unverifiable_fields {
            let known = if u.candidates.is_empty() {
                "no known values for this field".to_string()
            } else {
                format!("known values: {}", clean(&u.candidates.join(", ")))
            };
            out.push_str(&format!(
                "  {}: would send the literal value \"{}\" ({}); {known}.\n",
                clean(&u.field),
                clean(&u.would_send),
                u.reason
            ));
            if let Some(s) = &u.suggested {
                out.push_str(&format!("    suggestion: use `{}` instead.\n", clean(s)));
            }
        }
        out.push_str("  Ask the user. Only if they confirm a literal value, re-run with --allow-unverified <field>.\n");
    }
    if !report.allowed_unverified.is_empty() {
        out.push_str(&format!(
            "\nSent as typed (--allow-unverified): {}\n",
            clean(&report.allowed_unverified.join(", "))
        ));
    }
    if !report.not_applied.is_empty() {
        out.push_str("\n⚠ The record was partly updated (exit 9). The instance did not apply:\n");
        for n in &report.not_applied {
            out.push_str(&format!(
                "  {}: sent \"{}\", instance has \"{}\"\n",
                clean(&n.field),
                clean(&n.sent),
                clean(&n.returned)
            ));
        }
    }
    if !report.unconfirmed.is_empty() {
        out.push_str(&format!(
            "\nNot confirmed by the response: {}\n",
            clean(&report.unconfirmed.join(", "))
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_invocations_get_the_marker_and_interactive_ones_do_not() {
        // CT-38 (SAFE-8, NA-12)
        use crate::config::AgentMarkerMode::{Always, Auto};
        let marker = Some("[sncfr-agent]");
        assert!(agent_invocation(true, None, true, Auto), "--no-interactive");
        let (body, marked) = journal_payload("Rebooted the VPN gateway", marker, false).unwrap();
        assert!(marked);
        assert!(body.starts_with("[sncfr-agent] "), "{body}");

        // stdin is a TTY and stdout is piped (`| tee`): an interactive user, no marker.
        assert!(!agent_invocation(false, None, true, Auto));
        assert!(
            agent_invocation(false, Some("1"), true, Auto),
            "SNCFR_AGENT=1"
        );
        assert!(
            agent_invocation(false, None, false, Auto),
            "stdin not a TTY"
        );
        assert!(
            agent_invocation(false, None, true, Always),
            "profile always"
        );
        let (body, marked) = journal_payload("typed by hand", None, false).unwrap();
        assert_eq!((body.as_str(), marked), ("typed by hand", false));

        // Never doubled; `[code]` needs --allow-code-tag.
        let (again, _) = journal_payload("[sncfr-agent] x", marker, false).unwrap();
        assert_eq!(again, "[sncfr-agent] x");
        let err = journal_payload("[CODE]<b>x</b>[/code]", marker, false).unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        assert!(journal_payload("[code]<b>x</b>[/code]", marker, true).is_ok());
    }
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
            allow_code_tag: false,
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
            ..Default::default()
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
