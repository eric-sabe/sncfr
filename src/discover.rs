//! `sncfr discover`: probes the instance read-only and writes a **draft** Instance Pack
//! (DISC-4, DISC-5; spec §Discovery and §Pack author journey).
//!
//! Privacy (NA-8): the draft holds instance metadata only — prefixes, table and field names,
//! choice values and labels, capability states, and group-name suffix strings. Record contents,
//! sys_ids, user names, emails, display names, and full group names never reach it. Group names
//! are read in memory for suffix detection and dropped. `--no-samples` reads no record rows.

use crate::cache::{CachedChoice, InstanceCache};
use crate::capabilities::{CapSource, CapState, CapabilityRecord};
use crate::cli::DiscoverArgs;
use crate::client::{ReadOnlyClient, extract_field_value};
use crate::config::ResolvedProfile;
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::pack::MergedPack;
use crate::resolve::{fetch_sys_number, split_ticket_prefix};
use crate::resolve_value::{FieldType, ResolveCtx, fetch_in_use};
use crate::schema::load_or_sync_table_schema_with;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Rows sampled from `task` for prefix detection.
const TASK_SAMPLE: usize = 200;
/// Groups read (names only, in memory) for suffix detection.
const GROUP_SAMPLE: usize = 500;
/// A suffix is kept when at least this many group names end with it.
const MIN_SUFFIX_GROUPS: usize = 3;

pub const NEXT_STEPS: [&str; 5] = [
    "review each \"# observed\" comment and add values not seen",
    "sncfr pack validate <file>",
    "sncfr --pack <file> pack show",
    "set pack = \"<file>\" in [profiles.<p>], then sncfr doctor",
    "set status = \"active\" to allow writes",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverReport {
    pub path: String,
    pub status: String,
    pub prefixes: usize,
    pub choice_sets: usize,
    pub custom_fields: usize,
    pub suffixes: Vec<String>,
    pub no_samples: bool,
    pub next_steps: Vec<String>,
}

/// One observed prefix -> table mapping and how it was seen.
struct ObservedPrefix {
    table: String,
    note: String,
}

/// One probed choice field and what came back.
enum ChoiceOutcome {
    InUse(Vec<CachedChoice>),
    /// `sys_choice` gave a complete set; the pack needs no entry.
    Readable,
    /// Probed, no rows (or stats unavailable).
    Empty,
}

/// Runs the probes and writes the draft. Read-only: every request goes through `client`.
pub async fn execute_discover(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &DiscoverArgs,
) -> Result<DiscoverReport, SncfrError> {
    let path = match &args.out {
        Some(p) => p.clone(),
        None => default_draft_path(&profile.instance_key)?,
    };
    if path.exists() && !args.force {
        return Err(SncfrError::InvalidArgs {
            message: format!("'{}' already exists", path.display()),
            remediation: Some("Pass --force to overwrite it, or --out <file>.".to_string()),
        });
    }
    let pack = crate::pack::active();

    // 1. Capabilities (as `doctor --refresh`). Its table probes read one row id per table, so
    //    `--no-samples` records only what the metadata reads below observe.
    if args.no_samples {
        CapabilityRecord::clear(cache);
    } else {
        crate::doctor::execute_doctor_with(profile, client, cache, pack, true).await?;
    }

    // 2. Prefixes: sys_number, then (unless --no-samples) the most recent task rows.
    let ootb_prefixes = crate::pack::ootb_merged().prefix_map();
    let sys_number = fetch_sys_number(client, cache).await?;
    let mut prefixes: BTreeMap<String, ObservedPrefix> = BTreeMap::new();
    for (p, t) in sys_number.iter().flatten() {
        if ootb_prefixes.get(p) != Some(t) && crate::untrusted::is_table_name(t) {
            prefixes.insert(
                p.clone(),
                ObservedPrefix {
                    table: t.clone(),
                    note: format!("sys_number maps {p} -> {t}"),
                },
            );
        }
    }
    if !args.no_samples {
        for (p, (t, n, total)) in sample_task_prefixes(client).await? {
            if ootb_prefixes.get(&p) == Some(&t) || prefixes.contains_key(&p) {
                continue;
            }
            prefixes.insert(
                p.clone(),
                ObservedPrefix {
                    note: format!(
                        "{n} of the {total} most recent task rows use prefix {p} -> {t} (rarer prefixes may be missing; check sys_number or add them by hand)"
                    ),
                    table: t,
                },
            );
        }
    }

    // Tables to type and probe: incident, every table the pack lists, and newly seen tables.
    let mut tables: BTreeSet<String> = BTreeSet::from(["incident".to_string()]);
    tables.extend(
        pack.discovery_choice_fields
            .keys()
            .filter(|t| t.as_str() != "task")
            .cloned(),
    );
    tables.extend(prefixes.values().map(|p| p.table.clone()));
    tables.retain(|t| crate::untrusted::is_table_name(t));

    // 4. Custom field inventory (names and types only) and 3. choice fields via DISC-2.
    let mut custom: Vec<(String, String, String)> = Vec::new();
    let mut extra_choice_fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut choices: BTreeMap<(String, String), ChoiceOutcome> = BTreeMap::new();
    let mut skipped: Vec<String> = Vec::new();
    for table in &tables {
        let Ok(schema) =
            load_or_sync_table_schema_with(client, cache, table, true, !args.no_samples).await
        else {
            continue;
        };
        let ctx = ResolveCtx {
            pack,
            table,
            schema: &schema,
            sample: None,
            discovered: None,
        };
        let mut fields: Vec<String> = listed_fields(pack, table, schema.super_class.as_deref());
        if !args.no_samples {
            for (name, meta) in &schema.fields {
                if !meta.is_custom {
                    continue;
                }
                let choice_typed = meta.internal_type == "inferred_choice"
                    || schema.choices.get(name).is_some_and(|c| !c.is_empty());
                let kind = if choice_typed {
                    "choice-typed".to_string()
                } else {
                    match ctx.classify(name) {
                        FieldType::Reference { table: Some(t) } => format!("reference to {t}"),
                        FieldType::Reference { table: None } => "reference".to_string(),
                        FieldType::FreeText => "free text".to_string(),
                        _ => match meta.internal_type.strip_prefix("inferred") {
                            Some(_) => "untyped".to_string(),
                            None => meta.internal_type.clone(),
                        },
                    }
                };
                custom.push((table.clone(), name.clone(), kind));
                if choice_typed && !fields.contains(name) {
                    fields.push(name.clone());
                    extra_choice_fields
                        .entry(table.clone())
                        .or_default()
                        .push(name.clone());
                }
            }
        }
        let mut probe: Vec<&str> = Vec::new();
        for f in &fields {
            let listed_or_custom = ctx.discoverable(f)
                || extra_choice_fields
                    .get(table)
                    .is_some_and(|x| x.contains(f));
            if !listed_or_custom {
                skipped.push(format!("{table}.{f}"));
            } else if schema.choices.get(f).is_some_and(|c| !c.is_empty()) {
                choices.insert((table.clone(), f.clone()), ChoiceOutcome::Readable);
            } else {
                probe.push(f);
            }
        }
        let found = fetch_in_use(client, cache, table, &probe).await?;
        for f in probe {
            let outcome = match found.get(f) {
                Some(set) if !set.is_empty() => ChoiceOutcome::InUse(set.clone()),
                _ => ChoiceOutcome::Empty,
            };
            choices.insert((table.clone(), f.to_string()), outcome);
        }
    }

    // 5. Group suffixes (names in memory only).
    let suffixes = if args.no_samples {
        Vec::new()
    } else {
        group_suffixes(client).await?
    };

    let caps = CapabilityRecord::load(cache).statuses(pack);
    let draft = render_draft(&DraftInput {
        host: &profile.instance_key,
        no_samples: args.no_samples,
        sys_number_readable: sys_number.is_some(),
        caps: &caps,
        prefixes: &prefixes,
        pack,
        extra_choice_fields: &extra_choice_fields,
        custom: &custom,
        choices: &choices,
        skipped: &skipped,
        suffixes: &suffixes,
    });
    write_private(&path, &draft, args.force)?;

    Ok(DiscoverReport {
        path: path.display().to_string(),
        status: "draft".to_string(),
        prefixes: prefixes.len(),
        choice_sets: choices
            .values()
            .filter(|c| matches!(c, ChoiceOutcome::InUse(_)))
            .count(),
        custom_fields: custom.len(),
        suffixes: suffixes.iter().map(|(s, _)| s.clone()).collect(),
        no_samples: args.no_samples,
        next_steps: NEXT_STEPS.iter().map(|s| (*s).to_string()).collect(),
    })
}

/// `<config dir>/packs/<instance-host>.draft.pack.toml`.
fn default_draft_path(host: &str) -> Result<PathBuf, SncfrError> {
    let config = crate::config::default_config_path()?;
    let dir = config.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    Ok(dir.join("packs").join(format!("{host}.draft.pack.toml")))
}

/// Fields listed in `discovery.choice_fields` for `table` and its ancestors.
fn listed_fields(pack: &MergedPack, table: &str, super_class: Option<&str>) -> Vec<String> {
    let mut lineage = pack.lineage(table);
    if let Some(sc) = super_class
        && !lineage.iter().any(|t| t == sc)
    {
        lineage.push(sc.to_string());
    }
    let mut out: Vec<String> = Vec::new();
    for t in &lineage {
        for f in pack.discovery_choice_fields.get(t).into_iter().flatten() {
            if !out.contains(f) {
                out.push(f.clone());
            }
        }
    }
    out
}

/// Prefix -> (table, rows, rows sampled) from the most recent `task` rows (number and class only).
async fn sample_task_prefixes(
    client: &ReadOnlyClient,
) -> Result<BTreeMap<String, (String, usize, usize)>, SncfrError> {
    let limit = TASK_SAMPLE.to_string();
    let resp = match client
        .get_json::<Value>(
            "/api/now/table/task",
            &[
                ("sysparm_fields", "number,sys_class_name"),
                ("sysparm_limit", limit.as_str()),
                ("sysparm_query", "ORDERBYDESCsys_created_on"),
            ],
        )
        .await
    {
        Ok(v) => v,
        Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => {
            return Err(e);
        }
        Err(_) => return Ok(BTreeMap::new()),
    };
    let rows = resp
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in &rows {
        let (Some(number), Some(class)) = (
            extract_field_value(row, "number"),
            extract_field_value(row, "sys_class_name"),
        ) else {
            continue;
        };
        if let Some((prefix, _)) = split_ticket_prefix(&number)
            && crate::untrusted::is_table_name(&class)
        {
            *counts.entry((prefix, class)).or_default() += 1;
        }
    }
    // A prefix seen on several tables keeps its most frequent one.
    let mut out: BTreeMap<String, (String, usize, usize)> = BTreeMap::new();
    for ((prefix, table), n) in counts {
        let better = out.get(&prefix).is_none_or(|(_, best, _)| n > *best);
        if better {
            out.insert(prefix, (table, n, rows.len()));
        }
    }
    Ok(out)
}

/// Frequent trailing tokens of group names (after ` - `, `-`, or `_`), with how many names end
/// with each. Names are dropped once counted.
async fn group_suffixes(client: &ReadOnlyClient) -> Result<Vec<(String, usize)>, SncfrError> {
    let limit = GROUP_SAMPLE.to_string();
    let resp = match client
        .get_json::<Value>(
            "/api/now/table/sys_user_group",
            &[
                ("sysparm_fields", "name"),
                ("sysparm_limit", limit.as_str()),
            ],
        )
        .await
    {
        Ok(v) => v,
        Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => {
            return Err(e);
        }
        Err(_) => return Ok(Vec::new()),
    };
    let names: Vec<String> = resp
        .get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| extract_field_value(r, "name"))
        .collect();
    Ok(suffix_counts(&names))
}

/// The suffix detection itself (pure, for tests).
pub fn suffix_counts(names: &[String]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for name in names {
        let name = name.trim();
        for sep in [" - ", "-", "_"] {
            if let Some((head, tail)) = name.rsplit_once(sep)
                && !head.trim().is_empty()
                && !tail.is_empty()
                && tail.len() <= 12
                && !tail.contains(char::is_whitespace)
            {
                *counts.entry(format!("{sep}{tail}")).or_default() += 1;
                break;
            }
        }
    }
    counts
        .into_iter()
        .filter(|(s, n)| *n >= MIN_SUFFIX_GROUPS && crate::pack::validate::suffix_ok(s))
        .collect()
}

struct DraftInput<'a> {
    host: &'a str,
    no_samples: bool,
    sys_number_readable: bool,
    caps: &'a [crate::capabilities::CapStatus],
    prefixes: &'a BTreeMap<String, ObservedPrefix>,
    pack: &'a MergedPack,
    extra_choice_fields: &'a BTreeMap<String, Vec<String>>,
    custom: &'a [(String, String, String)],
    choices: &'a BTreeMap<(String, String), ChoiceOutcome>,
    skipped: &'a [String],
    suffixes: &'a [(String, usize)],
}

/// A TOML basic string (quoted and escaped).
fn q(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn render_draft(d: &DraftInput<'_>) -> String {
    let mut out = String::new();
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let _ = writeln!(
        out,
        "# Contains instance metadata. Do not commit to a public repository."
    );
    let _ = writeln!(
        out,
        "# Draft Instance Pack written by `sncfr discover` on {today}{}.",
        if d.no_samples {
            " with --no-samples (no record rows read)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "# Drafts never authorize writes. Review every \"# observed\" entry, add values not seen,"
    );
    let _ = writeln!(out, "# then set status = \"active\".\n");
    let _ = writeln!(out, "schema_version = 1");
    let _ = writeln!(
        out,
        "pack_version = {}",
        q(&format!("{}-draft", today.to_string().replace('-', ".")))
    );
    let _ = writeln!(out, "name = {}", q(&format!("{}-draft", d.host)));
    let _ = writeln!(out, "status = \"draft\"");
    let _ = writeln!(out, "instances = [{}]\n", q(d.host));

    // Capabilities: seeds only; live observation overrides them.
    let mut cap_lines = String::new();
    for c in d.caps {
        let seed = match c.state {
            CapState::Available => "true",
            CapState::Unavailable | CapState::Unauthorized => "false",
            CapState::Unknown => continue,
        };
        if c.source == CapSource::Pack.as_str() {
            continue;
        }
        let detail = match (c.http_status, c.hint) {
            (Some(s), Some(h)) => format!(
                " (HTTP {s}, {})",
                serde_json::json!(h).as_str().unwrap_or_default()
            ),
            (Some(s), None) => format!(" (HTTP {s})"),
            _ => String::new(),
        };
        let _ = writeln!(
            cap_lines,
            "# observed: {} = {}{detail}\n{} = {seed}",
            c.capability,
            c.state.as_str(),
            c.capability
        );
    }
    if !cap_lines.is_empty() {
        let _ = writeln!(
            out,
            "# Seeds only: true -> available, false -> unavailable. Live observation overrides them.\n[capabilities]\n{cap_lines}"
        );
    }

    // Prefixes.
    if d.prefixes.is_empty() {
        let why = match (d.sys_number_readable, d.no_samples) {
            (false, true) => " (sys_number unreadable, --no-samples set)",
            (false, false) => " beyond the bundled defaults (sys_number unreadable)",
            (true, _) => " beyond the bundled defaults",
        };
        let _ = writeln!(out, "# prefixes: none discovered{why}\n");
    } else {
        let _ = writeln!(out, "[prefixes]");
        for (p, o) in d.prefixes {
            let _ = writeln!(out, "# observed: {}\n{p} = {}", o.note, q(&o.table));
        }
        out.push('\n');
    }

    // Custom fields (names and types only).
    if !d.custom.is_empty() {
        for (t, f, kind) in d.custom {
            let _ = writeln!(out, "# custom field: {t}.{f} ({kind})");
        }
        out.push('\n');
    }

    // Choice sets.
    for ((t, f), outcome) in d.choices {
        match outcome {
            ChoiceOutcome::Readable => {
                let _ = writeln!(
                    out,
                    "# {t}.{f}: sys_choice is readable (a complete set); no pack entry needed\n"
                );
            }
            ChoiceOutcome::Empty => {}
            ChoiceOutcome::InUse(set) => {
                let _ = writeln!(
                    out,
                    "# in-use values only ({} seen). Values never used on this instance are missing; once status = \"active\", unlisted values are rejected.",
                    set.len()
                );
                let _ = writeln!(out, "[choices.{t}.{f}]\nvalues = [");
                let mut labels: BTreeMap<String, String> = BTreeMap::new();
                for c in set {
                    let key = c.label.trim().to_lowercase();
                    if let Some(prev) = labels.get(&key) {
                        let _ = writeln!(
                            out,
                            "  # observed label {} also on value {}; pick one by hand:\n  # {{ value = {}, label = {} }},",
                            q(&c.label),
                            q(prev),
                            q(&c.value),
                            q(&c.label)
                        );
                        continue;
                    }
                    labels.insert(key, c.value.clone());
                    let _ = writeln!(
                        out,
                        "  {{ value = {}, label = {} }},",
                        q(&c.value),
                        q(&c.label)
                    );
                }
                let _ = writeln!(out, "]\n");
            }
        }
    }
    let empty: Vec<String> = d
        .choices
        .iter()
        .filter(|(_, o)| matches!(o, ChoiceOutcome::Empty))
        .map(|((t, f), _)| format!("{t}.{f}"))
        .collect();
    if !empty.is_empty() {
        let _ = writeln!(
            out,
            "# no in-use values found (stats unavailable or no rows); add these sets by hand if needed:\n#   {}\n",
            empty.join(", ")
        );
    }
    for s in d.skipped {
        let _ = writeln!(
            out,
            "# skipped: {s} is listed in discovery.choice_fields but is a reference or free-text field (never probed)"
        );
    }
    if !d.skipped.is_empty() {
        out.push('\n');
    }

    // Discovery list: the merged one plus custom choice-typed fields.
    let mut lists: BTreeMap<String, Vec<String>> = d
        .pack
        .discovery_choice_fields
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (t, fs) in d.extra_choice_fields {
        let entry = lists.entry(t.clone()).or_default();
        for f in fs {
            if !entry.contains(f) {
                entry.push(f.clone());
            }
        }
    }
    if !lists.is_empty() {
        let body: Vec<String> = lists
            .iter()
            .map(|(t, fs)| {
                let items: Vec<String> = fs.iter().map(|f| q(f)).collect();
                format!("{t} = [{}]", items.join(", "))
            })
            .collect();
        let _ = writeln!(
            out,
            "[discovery]\nchoice_fields = {{ {} }}\n",
            body.join(", ")
        );
    }

    // Group suffixes.
    if d.suffixes.is_empty() {
        let _ = writeln!(
            out,
            "# groups: no suffix convention detected{}",
            if d.no_samples {
                " (not read: --no-samples set)"
            } else {
                ""
            }
        );
    } else {
        let _ = writeln!(out, "[groups]");
        for (s, n) in d.suffixes {
            let _ = writeln!(out, "# observed: {n} group names end with {}", q(s));
        }
        let items: Vec<String> = d.suffixes.iter().map(|(s, _)| q(s)).collect();
        let _ = writeln!(out, "suffixes = [{}]", items.join(", "));
    }
    out
}

/// Writes `text` with mode `0600`, refusing to replace an existing file unless `force`.
fn write_private(path: &Path, text: &str, force: bool) -> Result<(), SncfrError> {
    use std::io::Write as _;
    let fail = |e: std::io::Error| SncfrError::InvalidArgs {
        message: format!("Failed to write '{}': {e}", path.display()),
        remediation: None,
    };
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(fail)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(fail)?;
    }
    file.write_all(text.as_bytes()).map_err(fail)
}

pub fn format_discover_report(r: &DiscoverReport, format: ResolvedOutputFormat) -> String {
    if format == ResolvedOutputFormat::Json {
        return serde_json::to_string_pretty(r).unwrap_or_default();
    }
    let mut out = format!(
        "Wrote draft pack: {} (status = \"draft\")\n",
        crate::untrusted::inline(&r.path)
    );
    let _ = writeln!(
        out,
        "Found: {} prefix(es), {} in-use choice set(s), {} custom field(s), {} group suffix(es){}",
        r.prefixes,
        r.choice_sets,
        r.custom_fields,
        r.suffixes.len(),
        if r.no_samples {
            " (--no-samples: no record rows read)"
        } else {
            ""
        }
    );
    for (i, step) in r.next_steps.iter().enumerate() {
        let lead = if i == 0 { "Next: " } else { "      " };
        let _ = writeln!(out, "{lead}{}) {step}", i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes_need_three_groups_and_pass_the_suffix_rule() {
        let names: Vec<String> = [
            "Network - L2",
            "Storage - L2",
            "Ops, EMEA - L2",
            "Network - L3",
            "Payroll",
            "db_admins",
            "web_admins",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(suffix_counts(&names), vec![(" - L2".to_string(), 3)]);
    }

    #[test]
    fn toml_strings_round_trip() {
        for raw in ["a\"b", "it's", "back\\slash", "new\nline"] {
            let doc: toml::Table = toml::from_str(&format!("k = {}", q(raw))).expect("parse");
            assert_eq!(doc["k"].as_str(), Some(raw));
        }
    }
}
