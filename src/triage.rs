//! `sncfr triage` (TRI-1..7): one read-only digest of reason-coded buckets ("what needs my
//! attention now?") with explicit coverage.
//!
//! Every enabled bucket renders, in order, even when empty or degraded. Each bucket runs its own
//! queries concurrently and degrades on its own (CAP-3). Only `&ReadOnlyClient` is used (TRI-1,
//! NA-1).

use crate::cache::{CachedIdentity, InstanceCache};
use crate::cli::{ListFilterArgs, TriageArgs};
use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::config::ResolvedProfile;
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::pack::MergedPack;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;

/// The built-in buckets, in their default order (TRI-3).
pub const DEFAULT_BUCKETS: [&str; 5] = [
    "sla_at_risk",
    "customer_replied",
    "unassigned",
    "stale",
    "approvals",
];
const DEFAULT_PER_BUCKET: u32 = 10;
const MAX_PER_BUCKET: u32 = 50;
const DEFAULT_STALE: &str = "3d";
const DEFAULT_SLA_PCT: u8 = 75;
/// Candidate records examined for `customer_replied` before the journal check.
const REPLY_CANDIDATES: &str = "50";

/// Task fields every bucket reads (prefixed for `task_sla`).
const ITEM_FIELDS: [&str; 9] = [
    "sys_id",
    "number",
    "sys_class_name",
    "short_description",
    "priority",
    "sys_created_on",
    "sys_updated_on",
    "assigned_to",
    "assignment_group",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriagePriority {
    pub label: String,
    pub value: String,
    /// Where the label came from (`instance`: the record's own display value).
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageItem {
    pub bucket: String,
    /// Machine code (`SLA_BREACHED`, `UNASSIGNED`, `CUSTOM_VIP`, ...).
    pub reason_code: String,
    pub reason: String,
    pub number: String,
    pub short_description: String,
    pub priority: TriagePriority,
    /// Seconds since `sys_created_on`.
    pub age_secs: i64,
    /// Seconds since `sys_updated_on`.
    pub idle_secs: i64,
    pub age: String,
    pub idle: String,
    pub assigned_to: String,
    pub assignment_group: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_sys_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_by: Option<String>,
    /// Other buckets in this output that contain the same record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_in: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageBucket {
    pub name: String,
    /// `ok`, `approximate`, `restricted`, `unavailable`, `timed_out`, or `skipped`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub count: usize,
    pub has_more: bool,
    pub items: Vec<TriageItem>,
}

impl TriageBucket {
    fn checked(&self) -> bool {
        matches!(self.status.as_str(), "ok" | "approximate")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageEnvelope {
    /// The coverage line (`triage: 3 of 5 buckets checked · 14 items · not checked: ...`).
    pub summary: String,
    pub table: String,
    pub buckets: Vec<TriageBucket>,
}

/// Who and what the buckets look at (TRI-2).
#[derive(Debug, Clone)]
struct Scope {
    table: String,
    me_sys_id: String,
    me_user_name: String,
    /// `assignment_group…` predicate, when there is a group scope.
    groups: Option<String>,
    mine: bool,
    group_flag: bool,
    /// A saved view's query, ANDed into every bucket.
    view_query: Option<String>,
    per_bucket: u32,
    stale_since: DateTime<Utc>,
    sla_pct: u8,
    base_url: String,
}

impl Scope {
    /// Group-scoped buckets (`unassigned`, custom): `None` when they cannot run, with why.
    fn groups_only(&self) -> Result<String, String> {
        if self.mine {
            return Err("--mine limits triage to tickets assigned to you".to_string());
        }
        self.groups
            .clone()
            .ok_or_else(|| "you belong to no assignment groups; pass --group or --mine".to_string())
    }

    fn me(&self) -> String {
        format!("assigned_to={}", self.me_sys_id)
    }

    /// The default scope: my groups ∪ assigned to me (`--mine`/`--group` narrow it).
    fn union(&self) -> String {
        match (&self.groups, self.mine, self.group_flag) {
            (_, true, _) | (None, _, _) => self.me(),
            (Some(g), _, true) => g.clone(),
            (Some(g), _, false) => format!("{g}^OR{}", self.me()),
        }
    }
}

/// Executes `sncfr triage`.
pub async fn execute_triage(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &TriageArgs,
) -> Result<TriageEnvelope, SncfrError> {
    let pack = crate::pack::active();
    let now = Utc::now();
    let identity = crate::auth::resolve_current_identity(client, cache, false).await?;
    let (view_table, view_query) = match &args.view {
        Some(v) => {
            let sv = profile.resolve_saved_view(v)?;
            (Some(sv.table.clone()), Some(sv.query.clone()))
        }
        None => (None, None),
    };
    let table = args
        .table
        .clone()
        .map(|t| pack.resolve_table_shorthand(&t))
        .or(view_table)
        .unwrap_or_else(|| "task".to_string());
    if !crate::untrusted::is_table_name(&table) {
        return Err(SncfrError::InvalidArgs {
            message: format!(
                "'{}' is not a valid table name",
                crate::untrusted::inline(&table)
            ),
            remediation: None,
        });
    }
    let triage = pack.triage.clone();
    let per_bucket = args
        .per_bucket
        .or(triage.per_bucket)
        .unwrap_or(DEFAULT_PER_BUCKET)
        .clamp(1, MAX_PER_BUCKET);
    let stale = args
        .stale
        .clone()
        .or(triage.stale_after.clone())
        .unwrap_or_else(|| DEFAULT_STALE.to_string());
    let scope = Scope {
        groups: group_predicate(pack, &identity, args.group.as_deref())?,
        group_flag: args.group.is_some(),
        mine: args.mine,
        me_sys_id: identity.sys_id.clone(),
        me_user_name: identity.user_name.clone(),
        view_query,
        per_bucket,
        stale_since: crate::query::parse_since_to_utc(&stale, now)?,
        sla_pct: triage.sla_threshold_pct.unwrap_or(DEFAULT_SLA_PCT),
        base_url: client.base_url().as_str().trim_end_matches('/').to_string(),
        table,
    };

    let enabled = enabled_buckets(pack, &args.bucket)?;
    let runs = enabled
        .iter()
        .map(|name| run_bucket(client, cache, pack, &scope, name, now));
    let mut buckets: Vec<TriageBucket> = futures_util::future::join_all(runs).await;
    link_also_in(&mut buckets);
    let summary = coverage_line(&buckets);
    Ok(TriageEnvelope {
        summary,
        table: scope.table,
        buckets,
    })
}

/// `--bucket`, else pack `triage.buckets`, else the built-in order. Unknown names are exit 2.
fn enabled_buckets(pack: &MergedPack, requested: &[String]) -> Result<Vec<String>, SncfrError> {
    let known = |b: &str| DEFAULT_BUCKETS.contains(&b) || pack.triage.custom.contains_key(b);
    let list: Vec<String> = if !requested.is_empty() {
        requested.to_vec()
    } else if !pack.triage.buckets.is_empty() {
        pack.triage.buckets.clone()
    } else {
        DEFAULT_BUCKETS.iter().map(|b| (*b).to_string()).collect()
    };
    if let Some(bad) = list.iter().find(|b| !known(b)) {
        return Err(SncfrError::InvalidArgs {
            message: format!("unknown triage bucket '{}'", crate::untrusted::inline(bad)),
            remediation: Some(format!(
                "Buckets: {}{}.",
                DEFAULT_BUCKETS.join(", "),
                pack.triage
                    .custom
                    .keys()
                    .map(|k| format!(", {k}"))
                    .collect::<String>()
            )),
        });
    }
    Ok(list)
}

/// The group predicate (TRI-2, Q-5): `--group @my-groups` or none → my groups' sys_ids;
/// `--group <name>` → the name and its pack suffixes.
fn group_predicate(
    pack: &MergedPack,
    identity: &CachedIdentity,
    group: Option<&str>,
) -> Result<Option<String>, SncfrError> {
    match group.map(str::trim) {
        Some(name) if name != "@my-groups" => {
            let names = crate::query::expand_group_names(pack, name);
            if names.iter().any(|n| crate::untrusted::needs_or_chain(n)) {
                let mut terms = Vec::new();
                for n in &names {
                    terms.push(format!(
                        "assignment_group.name={}",
                        crate::untrusted::query_value(n)?
                    ));
                }
                Ok(Some(terms.join("^OR")))
            } else {
                for n in &names {
                    crate::untrusted::query_list_value(n)?;
                }
                Ok(Some(format!("assignment_group.nameIN{}", names.join(","))))
            }
        }
        _ => {
            let ids: Vec<&str> = identity
                .groups
                .iter()
                .map(|g| g.sys_id.as_str())
                .filter(|id| crate::untrusted::is_sys_id(id))
                .collect();
            Ok((!ids.is_empty()).then(|| format!("assignment_groupIN{}", ids.join(","))))
        }
    }
}

/// `scope ∧ extra ∧ view`, with the table's open rule (Q-2; per-child `^NQ` on `task`).
fn open_query(
    pack: &MergedPack,
    scope: &Scope,
    table: &str,
    predicate: &str,
    extra: &[String],
) -> Result<String, SncfrError> {
    let filters = ListFilterArgs {
        table: Some(table.to_string()),
        open: true,
        ..Default::default()
    };
    let plan = crate::query::plan_open_rules(pack, table, &filters)?;
    let mut eq = crate::query::EncodedQuery::new();
    eq.raw(predicate);
    for e in extra {
        eq.raw(e);
    }
    if let Some(v) = &scope.view_query {
        eq.raw(v);
    }
    Ok(eq.build_with(&plan))
}

fn status_of(err: &SncfrError) -> Option<(&'static str, String)> {
    match err {
        SncfrError::AclForbidden { resource, .. } => {
            Some(("restricted", format!("{resource} returned 403")))
        }
        SncfrError::NotFound { .. } => Some(("unavailable", "not found (404)".to_string())),
        SncfrError::TimedOut { .. } => Some(("timed_out", "timeout".to_string())),
        SncfrError::NetworkOrInstance { status, .. } => Some((
            "unavailable",
            status.map_or_else(|| "network error".to_string(), |s| format!("HTTP {s}")),
        )),
        SncfrError::RateLimited { .. } => Some(("unavailable", "rate limited (429)".to_string())),
        _ => None,
    }
}

fn degraded(name: &str, status: &str, detail: String) -> TriageBucket {
    TriageBucket {
        name: name.to_string(),
        status: status.to_string(),
        detail: Some(detail),
        ..Default::default()
    }
}

async fn read_rows(
    client: &ReadOnlyClient,
    table: &str,
    query: &str,
    fields: &str,
    limit: &str,
) -> Result<Vec<Value>, SncfrError> {
    let resp: Value = client
        .get_json(
            &format!("/api/now/table/{table}"),
            &[
                ("sysparm_query", query),
                ("sysparm_fields", fields),
                ("sysparm_display_value", "all"),
                ("sysparm_limit", limit),
            ],
        )
        .await?;
    Ok(resp
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Runs one bucket; failures become the bucket's status, never the command's error.
async fn run_bucket(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    pack: &MergedPack,
    scope: &Scope,
    name: &str,
    now: DateTime<Utc>,
) -> TriageBucket {
    let result = match name {
        "sla_at_risk" => sla_at_risk(client, scope, now).await,
        "customer_replied" => customer_replied(client, pack, scope, now).await,
        "unassigned" => match scope.groups_only() {
            Ok(g) => {
                simple(
                    client,
                    pack,
                    scope,
                    name,
                    &g,
                    &["assigned_toISEMPTY".to_string()],
                    ("UNASSIGNED", "no one is assigned"),
                    now,
                )
                .await
            }
            Err(why) => return degraded(name, "skipped", why),
        },
        "stale" => {
            let who = if scope.group_flag {
                scope.groups.clone().unwrap_or_else(|| scope.me())
            } else {
                scope.me()
            };
            let since = crate::query::format_servicenow_gmt(scope.stale_since);
            simple(
                client,
                pack,
                scope,
                name,
                &who,
                &[format!("sys_updated_on<{since}")],
                ("STALE", "no update since the stale cutoff"),
                now,
            )
            .await
        }
        "approvals" => approvals(client, cache, scope, now).await,
        custom => match (pack.triage.custom.get(custom), scope.groups_only()) {
            (Some(b), Ok(g)) => {
                let code = format!("CUSTOM_{}", custom.to_ascii_uppercase());
                let mut inner = scope.clone();
                inner.table.clone_from(&b.table);
                simple(
                    client,
                    pack,
                    &inner,
                    custom,
                    &g,
                    std::slice::from_ref(&b.query),
                    (&code, &b.reason),
                    now,
                )
                .await
            }
            (Some(_), Err(why)) => return degraded(name, "skipped", why),
            (None, _) => Err(SncfrError::InvalidArgs {
                message: format!("unknown bucket {custom}"),
                remediation: None,
            }),
        },
    };
    match result {
        Ok(mut b) => {
            b.name = name.to_string();
            b
        }
        Err(e) => match status_of(&e) {
            Some((status, detail)) => degraded(name, status, detail),
            None => degraded(name, "unavailable", e.code().as_str().to_ascii_lowercase()),
        },
    }
}

/// A bucket that is one open-rule query plus its predicates.
#[allow(clippy::too_many_arguments)]
async fn simple(
    client: &ReadOnlyClient,
    pack: &MergedPack,
    scope: &Scope,
    name: &str,
    who: &str,
    extra: &[String],
    (code, reason): (&str, &str),
    now: DateTime<Utc>,
) -> Result<TriageBucket, SncfrError> {
    let q = open_query(pack, scope, &scope.table, who, extra)?;
    let limit = (scope.per_bucket + 1).to_string();
    let rows = read_rows(client, &scope.table, &q, &ITEM_FIELDS.join(","), &limit).await?;
    Ok(finish(name, scope, rows, "", code, reason, now))
}

/// Builds the bucket from rows (fields under `prefix`), sorted per TRI-4 and capped.
fn finish(
    name: &str,
    scope: &Scope,
    rows: Vec<Value>,
    prefix: &str,
    code: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> TriageBucket {
    let mut items: Vec<TriageItem> = rows
        .iter()
        .map(|r| item_from(r, prefix, name, code, reason, scope, now))
        .collect();
    sort_items(&mut items);
    let has_more = items.len() > scope.per_bucket as usize;
    items.truncate(scope.per_bucket as usize);
    TriageBucket {
        name: name.to_string(),
        status: "ok".to_string(),
        detail: None,
        count: items.len(),
        has_more,
        items,
    }
}

fn parse_sn_time(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|n| n.and_utc())
}

/// `93784` → `1d 2h`.
pub fn human_duration(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h", s / 3600),
        _ => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

fn item_from(
    row: &Value,
    prefix: &str,
    bucket: &str,
    code: &str,
    reason: &str,
    scope: &Scope,
    now: DateTime<Utc>,
) -> TriageItem {
    let f = |k: &str| extract_field_display(row, &format!("{prefix}{k}")).unwrap_or_default();
    let v = |k: &str| extract_field_value(row, &format!("{prefix}{k}")).unwrap_or_default();
    let since = |k: &str| parse_sn_time(&v(k)).map_or(0, |t| (now - t).num_seconds());
    let (age_secs, idle_secs) = (since("sys_created_on"), since("sys_updated_on"));
    let class = Some(v("sys_class_name"))
        .filter(|c| crate::untrusted::is_table_name(c))
        .unwrap_or_else(|| scope.table.clone());
    TriageItem {
        bucket: bucket.to_string(),
        reason_code: code.to_string(),
        reason: reason.to_string(),
        number: f("number"),
        short_description: f("short_description"),
        priority: TriagePriority {
            label: f("priority"),
            value: v("priority"),
            source: "instance".to_string(),
        },
        age_secs,
        idle_secs,
        age: human_duration(age_secs),
        idle: human_duration(idle_secs),
        assigned_to: f("assigned_to"),
        assignment_group: f("assignment_group"),
        url: format!(
            "{}/nav_to.do?uri={class}.do?sys_id={}",
            scope.base_url,
            v("sys_id")
        ),
        ..Default::default()
    }
}

/// TRI-4: priority (numeric when every value is numeric, else by label), then idle descending.
fn sort_items(items: &mut [TriageItem]) {
    let numeric = items
        .iter()
        .all(|i| i.priority.value.parse::<i64>().is_ok());
    items.sort_by(|a, b| {
        let by_priority = if numeric {
            let n = |i: &TriageItem| i.priority.value.parse::<i64>().unwrap_or(i64::MAX);
            n(a).cmp(&n(b))
        } else {
            a.priority.label.cmp(&b.priority.label)
        };
        by_priority.then(b.idle_secs.cmp(&a.idle_secs))
    });
}

async fn sla_at_risk(
    client: &ReadOnlyClient,
    scope: &Scope,
    now: DateTime<Utc>,
) -> Result<TriageBucket, SncfrError> {
    let mut q = crate::query::prefix_terms(&scope.union(), "task.");
    if scope.table != "task" {
        let _ = write!(q, "^task.sys_class_name={}", scope.table);
    }
    if let Some(v) = &scope.view_query {
        let _ = write!(q, "^{}", crate::query::prefix_terms(v, "task."));
    }
    let _ = write!(
        q,
        "^stage=in_progress^has_breached=true^ORbusiness_percentage>={}",
        scope.sla_pct
    );
    let mut fields: Vec<String> = ITEM_FIELDS.iter().map(|f| format!("task.{f}")).collect();
    fields.push("has_breached".to_string());
    let limit = (scope.per_bucket + 1).to_string();
    let rows = read_rows(client, "task_sla", &q, &fields.join(","), &limit).await?;
    // One task can carry several SLAs; keep its first (most urgent) row.
    let mut seen = std::collections::BTreeSet::new();
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|r| seen.insert(extract_field_value(r, "task.sys_id").unwrap_or_default()))
        .collect();
    let mut b = finish(
        "sla_at_risk",
        scope,
        rows.clone(),
        "task.",
        "SLA_AT_RISK",
        "SLA nearing breach",
        now,
    );
    for item in &mut b.items {
        let breached = rows.iter().any(|r| {
            extract_field_display(r, "task.number").as_deref() == Some(item.number.as_str())
                && extract_field_value(r, "has_breached").is_some_and(|v| v == "true")
        });
        if breached {
            item.reason_code = "SLA_BREACHED".to_string();
            item.reason = "SLA breached".to_string();
        }
    }
    Ok(b)
}

/// TRI-3 `customer_replied`: my open records whose latest comment is the caller's and newer
/// than my own latest journal entry. One batched journal query reads authors and times only,
/// never `value`. A journal 403 switches to approximate mode.
async fn customer_replied(
    client: &ReadOnlyClient,
    pack: &MergedPack,
    scope: &Scope,
    now: DateTime<Utc>,
) -> Result<TriageBucket, SncfrError> {
    let mut caller_fields: Vec<String> = vec!["caller_id".to_string(), "requested_for".to_string()];
    for f in pack.core.caller_fields.values() {
        if !caller_fields.contains(f) {
            caller_fields.push(f.clone());
        }
    }
    let mut fields: Vec<String> = ITEM_FIELDS.iter().map(|f| (*f).to_string()).collect();
    fields.extend(caller_fields.iter().map(|c| format!("{c}.user_name")));
    let q = open_query(pack, scope, &scope.table, &scope.me(), &[])?;
    let records = read_rows(
        client,
        &scope.table,
        &q,
        &fields.join(","),
        REPLY_CANDIDATES,
    )
    .await?;
    let ids: Vec<String> = records
        .iter()
        .filter_map(|r| extract_field_value(r, "sys_id"))
        .filter(|id| crate::untrusted::is_sys_id(id))
        .collect();
    if ids.is_empty() {
        return Ok(finish(
            "customer_replied",
            scope,
            Vec::new(),
            "",
            "CUSTOMER_REPLIED",
            "",
            now,
        ));
    }
    let jq = format!(
        "element_idIN{}^elementINcomments,work_notes^ORDERBYDESCsys_created_on",
        ids.join(",")
    );
    let journal = match read_rows(
        client,
        "sys_journal_field",
        &jq,
        "element_id,element,sys_created_on,sys_created_by",
        "1000",
    )
    .await
    {
        Ok(rows) => rows,
        Err(SncfrError::AclForbidden { .. }) => {
            // Approximate mode: updated by someone else within the stale window.
            let since = crate::query::format_servicenow_gmt(scope.stale_since);
            let who = crate::untrusted::query_value(&scope.me_user_name)?;
            let q = open_query(
                pack,
                scope,
                &scope.table,
                &scope.me(),
                &[
                    format!("sys_updated_by!={who}"),
                    format!("sys_updated_on>{since}"),
                ],
            )?;
            let limit = (scope.per_bucket + 1).to_string();
            let rows = read_rows(client, &scope.table, &q, &ITEM_FIELDS.join(","), &limit).await?;
            let mut b = finish(
                "customer_replied",
                scope,
                rows,
                "",
                "UPDATED_BY_OTHER",
                "updated by someone else; comment author unknown",
                now,
            );
            b.status = "approximate".to_string();
            b.detail = Some("sys_journal_field returned 403".to_string());
            return Ok(b);
        }
        Err(e) => return Err(e),
    };
    let replied: Vec<Value> = records
        .into_iter()
        .filter(|r| {
            let id = extract_field_value(r, "sys_id").unwrap_or_default();
            let class =
                extract_field_value(r, "sys_class_name").unwrap_or_else(|| scope.table.clone());
            let caller =
                extract_field_value(r, &format!("{}.user_name", pack.caller_field(&class)))
                    .unwrap_or_default();
            let entries = journal
                .iter()
                .filter(|j| extract_field_value(j, "element_id").as_deref() == Some(id.as_str()));
            let time = |j: &Value| extract_field_value(j, "sys_created_on").unwrap_or_default();
            let latest_comment = entries
                .clone()
                .filter(|j| extract_field_value(j, "element").as_deref() == Some("comments"))
                .max_by_key(|j| time(j));
            let mine = entries
                .filter(|j| {
                    extract_field_value(j, "sys_created_by").as_deref()
                        == Some(scope.me_user_name.as_str())
                })
                .map(&time)
                .max()
                .unwrap_or_default();
            latest_comment.is_some_and(|c| {
                !caller.is_empty()
                    && extract_field_value(c, "sys_created_by").as_deref() == Some(caller.as_str())
                    && time(c) > mine
            })
        })
        .collect();
    Ok(finish(
        "customer_replied",
        scope,
        replied,
        "",
        "CUSTOMER_REPLIED",
        "the caller replied after your last update",
        now,
    ))
}

async fn approvals(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    scope: &Scope,
    now: DateTime<Utc>,
) -> Result<TriageBucket, SncfrError> {
    let env = crate::workflows::execute_approvals_list(
        client,
        cache,
        &crate::cli::ApprovalListArgs {
            state: "requested".to_string(),
            all_users: false,
        },
    )
    .await?;
    let mut items: Vec<TriageItem> = env
        .items
        .iter()
        .map(|a| {
            let doc = |k: &str| a.document.get(k).cloned().unwrap_or_default();
            let since = |k: &str| parse_sn_time(&doc(k).1).map_or(0, |t| (now - t).num_seconds());
            let class = Some(doc("sys_class_name").1)
                .filter(|c| crate::untrusted::is_table_name(c))
                .unwrap_or_else(|| "task".to_string());
            let (age_secs, idle_secs) = (since("sys_created_on"), since("sys_updated_on"));
            TriageItem {
                bucket: "approvals".to_string(),
                reason_code: "APPROVAL_PENDING".to_string(),
                reason: "your approval is pending".to_string(),
                number: Some(doc("number").0)
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| a.target_ticket.clone()),
                short_description: doc("short_description").0,
                priority: TriagePriority {
                    label: doc("priority").0,
                    value: doc("priority").1,
                    source: "instance".to_string(),
                },
                age_secs,
                idle_secs,
                age: human_duration(age_secs),
                idle: human_duration(idle_secs),
                assigned_to: doc("assigned_to").0,
                assignment_group: doc("assignment_group").0,
                url: format!(
                    "{}/nav_to.do?uri={class}.do?sys_id={}",
                    scope.base_url,
                    doc("sys_id").1
                ),
                approval_sys_id: Some(a.sys_id.clone()),
                linked_by: a.linked_by.clone(),
                also_in: Vec::new(),
            }
        })
        .collect();
    sort_items(&mut items);
    let has_more = items.len() > scope.per_bucket as usize;
    items.truncate(scope.per_bucket as usize);
    let mut b = TriageBucket {
        name: "approvals".to_string(),
        status: "ok".to_string(),
        count: items.len(),
        has_more,
        items,
        detail: None,
    };
    if !env.warnings.is_empty() {
        b.detail = Some(env.warnings.join(" "));
    }
    Ok(b)
}

/// `also_in`: the other buckets in this output that contain the same record.
fn link_also_in(buckets: &mut [TriageBucket]) {
    let index: Vec<(String, String)> = buckets
        .iter()
        .flat_map(|b| b.items.iter().map(|i| (i.number.clone(), b.name.clone())))
        .collect();
    for b in buckets.iter_mut() {
        for item in &mut b.items {
            item.also_in = index
                .iter()
                .filter(|(n, bucket)| n == &item.number && bucket != &b.name && !n.is_empty())
                .map(|(_, bucket)| bucket.clone())
                .collect();
        }
    }
}

/// `triage: 3 of 5 buckets checked · 14 items · not checked: sla_at_risk (403), ...`.
fn coverage_line(buckets: &[TriageBucket]) -> String {
    let checked = buckets.iter().filter(|b| b.checked()).count();
    let items: usize = buckets.iter().map(|b| b.count).sum();
    let mut line = format!(
        "triage: {checked} of {} buckets checked · {items} items",
        buckets.len()
    );
    let missing: Vec<String> = buckets
        .iter()
        .filter(|b| !b.checked())
        .map(|b| {
            let why = match b.status.as_str() {
                "restricted" => "403".to_string(),
                "timed_out" => "timeout".to_string(),
                other => other.to_string(),
            };
            format!("{} ({why})", b.name)
        })
        .collect();
    if !missing.is_empty() {
        let _ = write!(line, " · not checked: {}", missing.join(", "));
    }
    line
}

/// TRI-6: 0 when any bucket is `ok`/`approximate`. Otherwise `restricted → 4`,
/// `timed_out`/`unavailable → 7`, the most frequent wins, ties go to 7. `skipped` never counts,
/// and all-skipped is 0.
pub fn exit_code(buckets: &[TriageBucket]) -> u8 {
    if buckets.iter().any(TriageBucket::checked) {
        return 0;
    }
    let restricted = buckets.iter().filter(|b| b.status == "restricted").count();
    let failed = buckets
        .iter()
        .filter(|b| matches!(b.status.as_str(), "timed_out" | "unavailable"))
        .count();
    if restricted + failed == 0 {
        0
    } else if restricted > failed {
        4
    } else {
        7
    }
}

/// The error a non-zero triage exit maps to (the digest is printed first).
pub fn exit_error(env: &TriageEnvelope) -> Option<SncfrError> {
    match exit_code(&env.buckets) {
        4 => Some(SncfrError::AclForbidden {
            resource: "triage".to_string(),
            details: env.summary.clone(),
        }),
        7 => Some(SncfrError::NetworkOrInstance {
            message: env.summary.clone(),
            status: None,
            remediation: Some("Re-run later or with a longer --timeout.".to_string()),
        }),
        _ => None,
    }
}

pub fn format_triage(env: &TriageEnvelope, format: ResolvedOutputFormat) -> String {
    if format == ResolvedOutputFormat::Json {
        return serde_json::to_string_pretty(env).unwrap_or_default();
    }
    let md = format == ResolvedOutputFormat::Md;
    let cell = |s: &str| {
        if md {
            crate::untrusted::inline(s)
        } else {
            crate::untrusted::clean(s).replace('\n', " ⏎ ")
        }
    };
    let mut out = format!("{}\n", env.summary);
    for b in &env.buckets {
        let head = match b.status.as_str() {
            "ok" | "approximate" if b.items.is_empty() => format!("{}: 0 (checked)", b.name),
            "ok" => format!(
                "{}: {}{}",
                b.name,
                b.count,
                if b.has_more { "+" } else { "" }
            ),
            "approximate" => format!(
                "{}: {}{} (approximate: {})",
                b.name,
                b.count,
                if b.has_more { "+" } else { "" },
                cell(b.detail.as_deref().unwrap_or(""))
            ),
            _ => format!(
                "{}: not checked ({})",
                b.name,
                cell(b.detail.as_deref().unwrap_or(&b.status))
            ),
        };
        let _ = writeln!(out, "\n{}{head}", if md { "## " } else { "" });
        if b.items.is_empty() {
            continue;
        }
        if md {
            let _ = writeln!(
                out,
                "\n| Number | Priority | Idle | Assigned to | Reason | Short description |"
            );
            let _ = writeln!(out, "| :--- | :--- | :--- | :--- | :--- | :--- |");
        }
        for i in &b.items {
            let also = if i.also_in.is_empty() {
                String::new()
            } else {
                format!(" (also in {})", i.also_in.join(", "))
            };
            if md {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {}{also} | {} |",
                    cell(&i.number),
                    cell(&i.priority.label),
                    i.idle,
                    cell(&i.assigned_to),
                    cell(&i.reason),
                    cell(&i.short_description)
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {}  [{}]  idle {}  {}  — {}{also}",
                    cell(&i.number),
                    cell(&i.priority.label),
                    i.idle,
                    cell(&i.short_description),
                    cell(&i.reason)
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(name: &str, status: &str) -> TriageBucket {
        TriageBucket {
            name: name.to_string(),
            status: status.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn exit_follows_the_most_frequent_failure_with_ties_to_7() {
        // CT-44c (TRI-6)
        let b = [
            bucket("a", "restricted"),
            bucket("b", "restricted"),
            bucket("c", "timed_out"),
            bucket("d", "timed_out"),
            bucket("e", "skipped"),
        ];
        assert_eq!(exit_code(&b), 7, "tie → 7");
        assert_eq!(exit_code(&b[..3]), 4);
        assert_eq!(
            exit_code(&[bucket("a", "restricted"), bucket("b", "ok")]),
            0
        );
        assert_eq!(exit_code(&[bucket("a", "skipped")]), 0);
        assert_eq!(
            exit_code(&[bucket("a", "approximate"), bucket("b", "restricted")]),
            0
        );
    }

    #[test]
    fn markdown_cells_cannot_open_headings_or_cells() {
        // CT-45c (NA-9)
        let env = TriageEnvelope {
            summary: "triage: 1 of 1 buckets checked · 1 items".to_string(),
            table: "task".to_string(),
            buckets: vec![TriageBucket {
                name: "stale".to_string(),
                status: "ok".to_string(),
                count: 1,
                items: vec![TriageItem {
                    number: "INC0000001".to_string(),
                    short_description: "VPN\n## X |a|b|".to_string(),
                    reason: "stale".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let md = format_triage(&env, ResolvedOutputFormat::Md);
        assert!(!md.contains("\n## X"), "{md}");
        let row = md.lines().find(|l| l.contains("INC0000001")).expect("row");
        assert_eq!(row.matches(" | ").count() + 2, 7, "6 cells only: {row}");
        assert!(row.contains("\\|a\\|b\\|"), "{row}");
    }

    #[test]
    fn items_sort_by_priority_then_idle() {
        let it = |n: &str, p: &str, idle: i64| TriageItem {
            number: n.to_string(),
            priority: TriagePriority {
                value: p.to_string(),
                ..Default::default()
            },
            idle_secs: idle,
            ..Default::default()
        };
        let mut items = vec![it("c", "3", 10), it("a", "1", 5), it("b", "1", 50)];
        sort_items(&mut items);
        let order: Vec<&str> = items.iter().map(|i| i.number.as_str()).collect();
        assert_eq!(order, ["b", "a", "c"]);
        assert_eq!(human_duration(93_784), "1d 2h");
    }
}
