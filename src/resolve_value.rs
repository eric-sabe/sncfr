//! Field typing and fail-closed choice resolution (SAFE-1, SAFE-2, SAFE-5, SAFE-6; ADR-0002
//! amendment). See the normative outcome table in
//! `docs/specs/brownfield-instance-support.md` §Field typing and value resolution.

use crate::cache::{CachedChoice, CachedTableSchema};
use crate::client::{extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::pack::MergedPack;
use crate::pack::schema::{ChoiceSetFile, PackStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSource {
    /// An authoritative user-pack choice set.
    Pack,
    /// A `confirm_required` (e.g. bundled ootb) alias confirmed by instance metadata.
    Ootb,
    /// A cached `sys_choice` set.
    Cache,
    /// A live `sys_choice` set.
    SysChoice,
    /// An in-use set discovered via the Aggregate API (DISC-2).
    Discovered,
}

impl ValueSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Ootb => "ootb",
            Self::Cache => "cache",
            Self::SysChoice => "sys_choice",
            Self::Discovered => "discovered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnverifiableReason {
    /// No choice set exists for the field anywhere.
    NoMetadata,
    /// A discovered (incomplete, in-use) set exists, and the input matched nothing in it.
    NotSeen,
    /// An ootb alias matched the input, but the instance does not confirm its `(value, label)`.
    OotbUnconfirmed,
    /// The field name is not in the dictionary, the sample record, or the pack.
    UnknownField,
    /// The field exists, but its type can't be determined, so its value can't be checked.
    UnknownFieldType,
    /// A user-pack entry contradicts readable instance metadata.
    PackConflict,
    /// The value would come from a `draft` pack.
    DraftPack,
}

impl UnverifiableReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMetadata => "no_metadata",
            Self::NotSeen => "not_seen",
            Self::OotbUnconfirmed => "ootb_unconfirmed",
            Self::UnknownField => "unknown_field",
            Self::UnknownFieldType => "unknown_field_type",
            Self::PackConflict => "pack_conflict",
            Self::DraftPack => "draft_pack",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    Choice,
    Reference {
        table: Option<String>,
    },
    FreeText,
    /// Typed by the dictionary as a non-choice, non-reference scalar (integer, date, ...).
    Plain,
    Unknown,
    UnknownField,
}

/// The outcome of resolving one input for one field. Constructed only in this module and in
/// reference resolution, so a "verified" value always went through the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValue {
    value: String,
    label: Option<String>,
    source: Option<ValueSource>,
    unverifiable: Option<UnverifiableReason>,
    free_text: bool,
    candidates: Vec<(String, String)>,
    suggested: Option<String>,
}

impl ResolvedValue {
    /// The value that would be sent.
    pub fn value(&self) -> &str {
        &self.value
    }
    /// The label (display value), when known.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
    pub const fn source(&self) -> Option<ValueSource> {
        self.source
    }
    pub const fn unverifiable(&self) -> Option<UnverifiableReason> {
        self.unverifiable
    }
    pub const fn is_free_text(&self) -> bool {
        self.free_text
    }
    /// Known `(value, label)` pairs for an unverifiable value.
    pub fn candidates(&self) -> &[(String, String)] {
        &self.candidates
    }
    /// A candidate value whose label matches the input after the `"<value> - "` prefix.
    pub fn suggested(&self) -> Option<&str> {
        self.suggested.as_deref()
    }

    pub(crate) fn verified(
        value: String,
        label: Option<String>,
        source: Option<ValueSource>,
    ) -> Self {
        Self {
            value,
            label,
            source,
            unverifiable: None,
            free_text: false,
            candidates: Vec::new(),
            suggested: None,
        }
    }

    pub(crate) fn text(value: &str) -> Self {
        Self {
            free_text: true,
            ..Self::verified(value.to_string(), Some(value.to_string()), None)
        }
    }

    fn unverified(
        input: &str,
        reason: UnverifiableReason,
        candidates: Vec<(String, String)>,
    ) -> Self {
        let suggested = suggestion(input, &candidates);
        Self {
            value: input.trim().to_string(),
            label: None,
            source: None,
            unverifiable: Some(reason),
            free_text: false,
            candidates,
            suggested,
        }
    }

    /// Display label for previews (`UNVERIFIABLE` when unknown).
    pub fn display(&self) -> String {
        self.label.clone().unwrap_or_else(|| {
            if self.unverifiable.is_some() {
                "UNVERIFIABLE".to_string()
            } else {
                self.value.clone()
            }
        })
    }

    /// Preview `Source` column.
    pub fn source_label(&self) -> String {
        if self.free_text {
            "input".to_string()
        } else {
            self.source.map_or("none", ValueSource::as_str).to_string()
        }
    }

    /// Preview `Status` column.
    pub fn status_label(&self) -> String {
        match (self.unverifiable, self.free_text, self.source) {
            (Some(r), _, _) => format!("UNVERIFIABLE ({})", r.as_str()),
            (None, true, _) => "n/a (free text)".to_string(),
            (None, false, Some(ValueSource::Discovered)) => "verified (in-use set)".to_string(),
            (None, false, _) => "verified".to_string(),
        }
    }
}

/// `"5 - Low"` → `"low"`; `"Low"` → `"low"`.
fn label_core(label: &str) -> String {
    let l = label.trim();
    let core = match l.split_once(" - ") {
        Some((head, tail)) if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) => tail,
        _ => l,
    };
    core.to_lowercase()
}

fn suggestion(input: &str, candidates: &[(String, String)]) -> Option<String> {
    let want = input.trim().to_lowercase();
    let mut hits = candidates
        .iter()
        .filter(|(_, label)| label_core(label) == want);
    match (hits.next(), hits.next()) {
        (Some((value, _)), None) => Some(value.clone()),
        _ => None,
    }
}

/// Everything resolution needs about one target table.
pub struct ResolveCtx<'a> {
    pub pack: &'a MergedPack,
    pub table: &'a str,
    pub schema: &'a CachedTableSchema,
    /// The target record (update) or a sample row (create), `sysparm_display_value=all`.
    pub sample: Option<&'a Value>,
    /// In-use sets from the Aggregate API (DISC-2), keyed by field ([`discover_in_use`]).
    pub discovered: Option<&'a BTreeMap<String, Vec<CachedChoice>>>,
}

impl ResolveCtx<'_> {
    /// `table`, then its ancestors (pack `[hierarchy]`, then the schema's super class).
    fn lineage(&self) -> Vec<String> {
        let mut chain = vec![self.table.to_string()];
        let mut cur = self.table.to_string();
        while let Some(parent) = self.pack.hierarchy.get(&cur).map(|p| p.value.clone()) {
            if chain.contains(&parent) {
                break;
            }
            chain.push(parent.clone());
            cur = parent;
        }
        if let Some(sc) = &self.schema.super_class
            && !chain.contains(sc)
        {
            chain.push(sc.clone());
        }
        chain
    }

    fn pack_set(
        &self,
        field: &str,
        confirm_required: bool,
    ) -> Option<&crate::pack::Sourced<ChoiceSetFile>> {
        self.lineage().iter().find_map(|t| {
            self.pack
                .choices
                .get(&format!("{t}.{field}"))
                .filter(|s| s.value.confirm_required == confirm_required)
        })
    }

    fn instance_set(&self, field: &str) -> Option<(&[CachedChoice], ValueSource)> {
        self.schema
            .choices
            .get(field)
            .filter(|c| !c.is_empty())
            .map(|c| {
                let source = if self.schema.loaded_from_cache {
                    ValueSource::Cache
                } else {
                    ValueSource::SysChoice
                };
                (c.as_slice(), source)
            })
    }

    fn in_discovery_list(&self, field: &str) -> bool {
        self.lineage().iter().any(|t| {
            self.pack
                .discovery_choice_fields
                .get(t)
                .is_some_and(|fs| fs.iter().any(|f| f == field))
        })
    }

    /// Types a field from the dictionary, the pack, and the sample record (see the spec table).
    pub fn classify(&self, field: &str) -> FieldType {
        let meta = self.schema.fields.get(field);
        let dict_typed = meta.filter(|m| !m.internal_type.starts_with("inferred"));
        if let Some(m) = dict_typed
            && m.internal_type == "reference"
        {
            return FieldType::Reference {
                table: m.reference_table.clone(),
            };
        }
        if field == "assigned_to"
            || field == "assignment_group"
            || self.pack.core.caller_fields.values().any(|f| f == field)
            || field == "opened_by"
        {
            return FieldType::Reference { table: None };
        }
        if self.instance_set(field).is_some()
            || self.pack_set(field, false).is_some()
            || self.pack_set(field, true).is_some()
            || self.in_discovery_list(field)
        {
            return FieldType::Choice;
        }
        if self.pack.core.known_free_text.iter().any(|f| f == field) {
            return FieldType::FreeText;
        }
        match meta.map(|m| m.internal_type.as_str()) {
            Some("inferred_choice") => return FieldType::Choice,
            Some("inferred_reference") => {
                return FieldType::Reference {
                    table: meta.and_then(|m| m.reference_table.clone()),
                };
            }
            _ => {}
        }
        if let Some(m) = dict_typed {
            return match m.internal_type.as_str() {
                "string" | "html" | "journal" | "journal_input" | "translated_text"
                | "translated_html" | "email" | "url" | "multi_two_lines" => FieldType::FreeText,
                _ => FieldType::Plain,
            };
        }
        if let Some(sample) = self.sample
            && sample.get(field).is_some()
        {
            let value = extract_field_value(sample, field).unwrap_or_default();
            let display = extract_field_display(sample, field).unwrap_or_default();
            if let Some(link) = sample.get(field).and_then(|v| v.get("link")) {
                return FieldType::Reference {
                    table: link.as_str().and_then(crate::untrusted::link_table),
                };
            }
            if !value.is_empty() && display != value {
                return FieldType::Choice;
            }
            return FieldType::Unknown;
        }
        if meta.is_some() {
            return FieldType::Unknown;
        }
        FieldType::UnknownField
    }
}

fn pairs(set: &[CachedChoice]) -> Vec<(String, String)> {
    set.iter()
        .map(|c| (c.value.clone(), c.label.clone()))
        .collect()
}

fn valid_choices(pairs: &[(String, String)], suggested: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(s) = suggested
        && let Some((v, l)) = pairs.iter().find(|(v, _)| v == s)
    {
        out.push(format!("{l} ({v})"));
    }
    for (v, l) in pairs {
        let item = format!("{l} ({v})");
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn ambiguous(field: &str, input: &str, matches: &[(String, String)]) -> SncfrError {
    SncfrError::Validation {
        message: format!("'{input}' matches more than one value of '{field}'"),
        valid_choices: valid_choices(matches, None),
        remediation: Some(format!(
            "Pass the exact value for '{field}' (e.g. `--set {field}=<value>`)."
        )),
    }
}

/// Distinct `(value, label)` pairs in `set` matched by `input` (exact value, or case-insensitive
/// label).
fn direct_matches(set: &[CachedChoice], input: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for c in set {
        if (c.value == input || c.label.eq_ignore_ascii_case(input))
            && !out.iter().any(|(v, _)| *v == c.value)
        {
            out.push((c.value.clone(), c.label.clone()));
        }
    }
    out
}

/// Distinct `(value, label)` entries of a pack set matched by value, label, or alias.
fn pack_matches(set: &ChoiceSetFile, input: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for e in &set.values {
        let hit = e.value == input
            || e.label.eq_ignore_ascii_case(input)
            || e.aliases.iter().any(|a| a.eq_ignore_ascii_case(input));
        if hit && !out.iter().any(|(v, _)| *v == e.value) {
            out.push((e.value.clone(), e.label.clone()));
        }
    }
    out
}

/// Resolves `input` for a choice-typed `field` through the chain. `Err` only for exit-2 cases
/// (no match in a complete set, or ambiguity).
pub fn resolve_choice(
    ctx: &ResolveCtx<'_>,
    field: &str,
    input: &str,
) -> Result<ResolvedValue, SncfrError> {
    let input = input.trim();
    let instance = ctx.instance_set(field);

    // 1. Authoritative pack set.
    if let Some(set) = ctx.pack_set(field, false) {
        let matched = pack_matches(&set.value, input);
        let entries: Vec<(String, String)> = set
            .value
            .values
            .iter()
            .map(|e| (e.value.clone(), e.label.clone()))
            .collect();
        return match matched.as_slice() {
            [] => Err(SncfrError::Validation {
                message: format!(
                    "'{input}' is not a value of '{field}' in the Instance Pack '{}'",
                    ctx.pack.name
                ),
                valid_choices: valid_choices(&entries, suggestion(input, &entries).as_deref()),
                remediation: Some(
                    "The pack's choice set is complete; use one of the listed values.".to_string(),
                ),
            }),
            [(value, label)] => {
                if ctx.pack.status == PackStatus::Draft {
                    let mut r =
                        ResolvedValue::unverified(value, UnverifiableReason::DraftPack, entries);
                    r.label = Some(label.clone());
                    return Ok(r);
                }
                if let Some((inst, _)) = instance
                    && !set.value.workaround
                    && !inst.iter().any(|c| &c.value == value && c.label == *label)
                {
                    let mut r = ResolvedValue::unverified(
                        value,
                        UnverifiableReason::PackConflict,
                        pairs(inst),
                    );
                    r.label = Some(label.clone());
                    return Ok(r);
                }
                Ok(ResolvedValue::verified(
                    value.clone(),
                    Some(label.clone()),
                    Some(ValueSource::Pack),
                ))
            }
            many => Err(ambiguous(field, input, many)),
        };
    }

    // 2. Complete instance set (cached or live sys_choice), with confirm-only aliases.
    if let Some((inst, source)) = instance {
        let direct = direct_matches(inst, input);
        match direct.as_slice() {
            [(value, label)] => {
                return Ok(ResolvedValue::verified(
                    value.clone(),
                    Some(label.clone()),
                    Some(source),
                ));
            }
            [] => {}
            many => return Err(ambiguous(field, input, many)),
        }
        if let Some(confirm) = ctx.pack_set(field, true) {
            let confirmed: Vec<(String, String)> = pack_matches(&confirm.value, input)
                .into_iter()
                .filter(|(v, l)| inst.iter().any(|c| &c.value == v && &c.label == l))
                .collect();
            match confirmed.as_slice() {
                [(value, label)] => {
                    let src = if confirm.origin == crate::pack::PackOrigin::Ootb {
                        ValueSource::Ootb
                    } else {
                        ValueSource::Pack
                    };
                    return Ok(ResolvedValue::verified(
                        value.clone(),
                        Some(label.clone()),
                        Some(src),
                    ));
                }
                [] => {}
                many => return Err(ambiguous(field, input, many)),
            }
        }
        let known = pairs(inst);
        return Err(SncfrError::Validation {
            message: format!(
                "Invalid value '{input}' for field '{field}' on table '{}'",
                ctx.table
            ),
            valid_choices: valid_choices(&known, suggestion(input, &known).as_deref()),
            remediation: Some(format!(
                "Use one of the valid '{field}' choices listed above."
            )),
        });
    }

    // 3. In-use (discovered) set (DISC-2, DISC-3): it cannot prove a value doesn't exist.
    if let Some(found) = ctx
        .discovered
        .and_then(|d| d.get(field))
        .filter(|s| !s.is_empty())
    {
        let direct = direct_matches(found, input);
        match direct.as_slice() {
            [(value, label)] => {
                return Ok(ResolvedValue::verified(
                    value.clone(),
                    Some(label.clone()),
                    Some(ValueSource::Discovered),
                ));
            }
            [] => {}
            many => return Err(ambiguous(field, input, many)),
        }
        let mut alias_matched = false;
        if let Some(confirm) = ctx.pack_set(field, true) {
            let candidates = pack_matches(&confirm.value, input);
            alias_matched = !candidates.is_empty();
            let confirmed: Vec<(String, String)> = candidates
                .into_iter()
                .filter(|(v, l)| found.iter().any(|c| &c.value == v && &c.label == l))
                .collect();
            if let [(value, label)] = confirmed.as_slice() {
                let src = if confirm.origin == crate::pack::PackOrigin::Ootb {
                    ValueSource::Ootb
                } else {
                    ValueSource::Pack
                };
                return Ok(ResolvedValue::verified(
                    value.clone(),
                    Some(label.clone()),
                    Some(src),
                ));
            }
        }
        let reason = if alias_matched {
            UnverifiableReason::OotbUnconfirmed
        } else {
            UnverifiableReason::NotSeen
        };
        return Ok(ResolvedValue::unverified(input, reason, pairs(found)));
    }

    // 4. Nothing to check against.
    Ok(ResolvedValue::unverified(
        input,
        UnverifiableReason::NoMetadata,
        Vec::new(),
    ))
}

/// Resolves a value for any field: typing first, then the choice chain for choice fields.
/// Reference fields are resolved by their dedicated flags; a raw sys_id passes, anything else is
/// `NoMetadata` here (reference lookups by name happen in `references`).
pub fn resolve_field(
    ctx: &ResolveCtx<'_>,
    field: &str,
    input: &str,
) -> Result<ResolvedValue, SncfrError> {
    match ctx.classify(field) {
        FieldType::Choice => resolve_choice(ctx, field, input),
        FieldType::FreeText => Ok(ResolvedValue::text(input)),
        FieldType::Plain => Ok(ResolvedValue::verified(
            input.to_string(),
            Some(input.to_string()),
            None,
        )),
        FieldType::Reference { .. } if crate::untrusted::is_sys_id(input.trim()) => Ok(
            ResolvedValue::verified(input.trim().to_string(), None, None),
        ),
        FieldType::Reference { .. } => Ok(ResolvedValue::unverified(
            input,
            UnverifiableReason::NoMetadata,
            Vec::new(),
        )),
        FieldType::Unknown => Ok(ResolvedValue::unverified(
            input,
            UnverifiableReason::UnknownFieldType,
            Vec::new(),
        )),
        FieldType::UnknownField => Ok(ResolvedValue::unverified(
            input,
            UnverifiableReason::UnknownField,
            Vec::new(),
        )),
    }
}

/// Dictionary types that are never probed for in-use values, even when listed (DISC-2 scope).
const NOT_DISCOVERABLE: &[&str] = &[
    "reference",
    "string",
    "html",
    "journal",
    "journal_input",
    "journal_list",
    "translated_text",
    "translated_html",
    "email",
    "url",
    "phone_number",
    "ph_number",
    "phone_number_e164",
    "multi_two_lines",
];

impl ResolveCtx<'_> {
    /// Whether resolution would reach step 3 for `field`: no pack set and no complete instance
    /// set, the field is `Choice`-typed and listed in `discovery.choice_fields`, and nothing marks
    /// it as a reference or free text.
    pub fn wants_discovery(&self, field: &str) -> bool {
        self.pack_set(field, false).is_none()
            && self.instance_set(field).is_none()
            && self.discoverable(field)
    }

    /// Whether `field` may be probed for in-use values at all (DISC-2 scope): listed in
    /// `discovery.choice_fields` (task-inherited), `Choice`-typed, and not marked as a reference
    /// or free text by the dictionary or the sample. `discover` uses this directly, since it
    /// describes the instance rather than the pack.
    pub fn discoverable(&self, field: &str) -> bool {
        if !self.in_discovery_list(field) || self.classify(field) != FieldType::Choice {
            return false;
        }
        let excluded_type = self.schema.fields.get(field).and_then(|m| {
            (m.internal_type == "inferred_reference"
                || NOT_DISCOVERABLE.contains(&m.internal_type.as_str()))
            .then_some(m.internal_type.as_str())
        });
        let sampled_link = self
            .sample
            .and_then(|s| s.get(field))
            .and_then(|v| v.get("link"))
            .is_some();
        if let Some(t) = excluded_type.or(sampled_link.then_some("inferred_reference")) {
            crate::debug_log!(
                "discovery",
                "{}.{field} is listed in discovery.choice_fields but typed {t}; not probed",
                self.table
            );
            return false;
        }
        true
    }
}

/// In-use choice sets for one table, cached in `discovered/<table>.json`. Always incomplete:
/// values never used on the instance are missing (DISC-3). A field probed with no rows is kept as
/// an empty set so a re-run inside the TTL sends no request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredSets {
    /// Always `discovered`.
    pub source: String,
    /// Always `false`.
    pub complete: bool,
    #[serde(default)]
    pub fields: BTreeMap<String, Vec<CachedChoice>>,
}

fn discovered_path(table: &str) -> std::path::PathBuf {
    std::path::Path::new("discovered").join(format!("{table}.json"))
}

/// `(value, label)` pairs for `field` in an Aggregate API `group_by` response (labels only;
/// counts are not kept).
pub fn parse_in_use(resp: &Value, field: &str) -> Vec<CachedChoice> {
    let mut out: Vec<CachedChoice> = Vec::new();
    for item in resp
        .get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(gf) = item
            .get("groupby_fields")
            .and_then(Value::as_array)
            .and_then(|g| {
                g.iter()
                    .find(|f| f.get("field").and_then(Value::as_str) == Some(field))
            })
        else {
            continue;
        };
        let value = gf.get("value").and_then(Value::as_str).unwrap_or_default();
        if value.is_empty() || out.iter().any(|c| c.value == value) {
            continue;
        }
        let label = gf
            .get("display_value")
            .and_then(Value::as_str)
            .filter(|d| !d.is_empty())
            .unwrap_or(value);
        out.push(CachedChoice {
            label: label.to_string(),
            value: value.to_string(),
            sequence: None,
        });
    }
    out
}

/// Step 3's input (DISC-2): in-use sets for each of `fields` that [`ResolveCtx::wants_discovery`],
/// from `discovered/<table>.json` within its TTL, else one
/// `/api/now/stats/<table>?sysparm_group_by=<field>` request per field. A capability record of
/// `stats_group_by` other than available/unknown skips the request. Observes `stats_group_by`.
pub async fn discover_in_use(
    client: &crate::client::ReadOnlyClient,
    cache: &crate::cache::InstanceCache,
    ctx: &ResolveCtx<'_>,
    fields: &[&str],
) -> Result<BTreeMap<String, Vec<CachedChoice>>, SncfrError> {
    let wanted: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|f| ctx.wants_discovery(f))
        .collect();
    fetch_in_use(client, cache, ctx.table, &wanted).await
}

/// In-use sets for `fields` of `table`: cached entries within the TTL, else one stats request per
/// field. A field whose in-use values are sys_ids is a reference, not a choice, and is kept as an
/// empty set so no names reach the cache.
pub async fn fetch_in_use(
    client: &crate::client::ReadOnlyClient,
    cache: &crate::cache::InstanceCache,
    table: &str,
    wanted: &[&str],
) -> Result<BTreeMap<String, Vec<CachedChoice>>, SncfrError> {
    use crate::capabilities::{CapHint, CapSource, CapState, Capability, CapabilityRecord};
    if wanted.is_empty() {
        return Ok(BTreeMap::new());
    }
    let path = discovered_path(table);
    let mut sets: DiscoveredSets = cache.read_fresh(&path).ok().flatten().unwrap_or_default();
    let mut changed = false;
    for field in wanted {
        if sets.fields.contains_key(*field) {
            continue;
        }
        if !crate::capabilities::state(cache, Capability::StatsGroupBy).worth_trying() {
            break;
        }
        let stats_path = format!("/api/now/stats/{table}");
        match client
            .get_json::<Value>(
                &stats_path,
                &[
                    ("sysparm_count", "true"),
                    ("sysparm_group_by", field),
                    ("sysparm_display_value", "all"),
                ],
            )
            .await
        {
            Ok(resp) => {
                CapabilityRecord::observe(
                    cache,
                    Capability::StatsGroupBy,
                    CapState::Available,
                    CapSource::Observed,
                    Some(200),
                    None,
                );
                let mut set = parse_in_use(&resp, field);
                if set.iter().any(|c| crate::untrusted::is_sys_id(&c.value)) {
                    crate::debug_log!(
                        "discovery",
                        "{table}.{field}: in-use values are sys_ids (a reference); not kept"
                    );
                    set.clear();
                }
                sets.fields.insert((*field).to_string(), set);
                changed = true;
            }
            Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => {
                return Err(e);
            }
            Err(SncfrError::AclForbidden { .. }) => {
                CapabilityRecord::observe(
                    cache,
                    Capability::StatsGroupBy,
                    CapState::Unauthorized,
                    CapSource::Observed,
                    Some(403),
                    Some(CapHint::Acl),
                );
                break;
            }
            // Anything else (a missing table, 5xx, timeout) leaves step 3 without a set this run.
            Err(_) => {}
        }
    }
    if changed {
        sets.source = "discovered".to_string();
        sets.complete = false;
        let _ = cache.write_entry(&path, &sets, crate::cache::DEFAULT_SCHEMA_TTL_SECS);
    }
    Ok(sets
        .fields
        .into_iter()
        .filter(|(f, _)| wanted.contains(&f.as_str()))
        .collect())
}

/// A read filter value that could not be verified; it is sent as typed and reported in-band
/// (Q-1). UNVERIFIABLE never blocks a read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiedFilter {
    pub field: String,
    pub input: String,
    pub sent: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

impl ResolveCtx<'_> {
    /// True when the pack or the instance defines a choice set for `field` on this table (or,
    /// for the pack, an ancestor).
    pub fn defines(&self, field: &str) -> bool {
        self.instance_set(field).is_some() || self.pack_set(field, false).is_some()
    }
}

/// Q-1 for a `task`-level query with no `task`-level definition: every child table whose set is
/// known must agree on the value, or the query is ambiguous (exit 2, naming the tables).
/// Returns `None` when no child defines the field.
pub fn resolve_across_children(
    pack: &MergedPack,
    field: &str,
    input: &str,
    children: &[(String, CachedTableSchema)],
) -> Result<Option<ResolvedValue>, SncfrError> {
    let mut outcomes: Vec<(String, Option<ResolvedValue>)> = Vec::new();
    for (table, schema) in children {
        let ctx = ResolveCtx {
            pack,
            table,
            schema,
            sample: None,
            discovered: None,
        };
        if !ctx.defines(field) {
            continue;
        }
        match resolve_choice(&ctx, field, input) {
            Ok(v) if v.unverifiable().is_none() => outcomes.push((table.clone(), Some(v))),
            Ok(_) => {}
            Err(_) => outcomes.push((table.clone(), None)),
        }
    }
    let Some((_, first)) = outcomes.first() else {
        return Ok(None);
    };
    let agree = outcomes.iter().all(|(_, v)| match (v, first) {
        (Some(a), Some(b)) => a.value() == b.value(),
        _ => false,
    });
    if agree {
        return Ok(first.clone());
    }
    Err(SncfrError::Validation {
        message: format!(
            "'{input}' means different things for '{field}' across task tables; filter one table with --table"
        ),
        valid_choices: outcomes
            .iter()
            .map(|(t, v)| match v {
                Some(v) => format!("{t}: {} ({})", v.display(), v.value()),
                None => format!("{t}: no such value"),
            })
            .collect(),
        remediation: Some(format!(
            "Re-run with `--table <table>` so '{field}' has one meaning."
        )),
    })
}

/// Resolves `--state` / `--priority` for a read against `table` (Q-1). Verified values replace
/// the input; unverifiable ones are sent as typed and returned for in-band reporting; ambiguity
/// and divergence are exit 2.
pub async fn resolve_read_filters(
    client: &crate::client::ReadOnlyClient,
    cache: &crate::cache::InstanceCache,
    table: &str,
    filters: &crate::cli::ListFilterArgs,
) -> Result<(crate::cli::ListFilterArgs, Vec<UnverifiedFilter>), SncfrError> {
    let mut resolved = filters.clone();
    let mut unverified = Vec::new();
    if filters.state.is_empty() && filters.priority.is_empty() {
        return Ok((resolved, unverified));
    }
    let pack = crate::pack::active();
    let schema = crate::schema::load_or_sync_table_schema(client, cache, table, false).await?;
    let probe = ResolveCtx {
        pack,
        table,
        schema: &schema,
        sample: None,
        discovered: None,
    };
    let wanted: Vec<&str> = [("state", &filters.state), ("priority", &filters.priority)]
        .iter()
        .filter(|(_, inputs)| !inputs.is_empty())
        .map(|(f, _)| *f)
        .collect();
    let discovered = discover_in_use(client, cache, &probe, &wanted).await?;
    let ctx = ResolveCtx {
        discovered: Some(&discovered),
        ..probe
    };
    let children: Vec<(String, CachedTableSchema)> =
        if table == "task" {
            pack.hierarchy
                .iter()
                .filter(|(_, parent)| parent.value == "task")
                .map(|(child, _)| {
                    // Pack sets or the schema cache only: no extra request per child table.
                    let s = cache.read_table_schema(child).ok().flatten().unwrap_or(
                        CachedTableSchema {
                            table: child.clone(),
                            super_class: Some("task".to_string()),
                            fields: BTreeMap::new(),
                            choices: BTreeMap::new(),
                            loaded_from_cache: true,
                        },
                    );
                    (child.clone(), s)
                })
                .collect()
        } else {
            Vec::new()
        };
    for (field, inputs, out) in [
        ("state", &filters.state, &mut resolved.state),
        ("priority", &filters.priority, &mut resolved.priority),
    ] {
        out.clear();
        for input in inputs {
            let value = if table == "task" && !ctx.defines(field) {
                match resolve_across_children(pack, field, input, &children)? {
                    Some(v) => v,
                    None => resolve_choice(&ctx, field, input)?,
                }
            } else {
                resolve_choice(&ctx, field, input)?
            };
            if let Some(reason) = value.unverifiable() {
                unverified.push(UnverifiedFilter {
                    field: field.to_string(),
                    input: input.clone(),
                    sent: value.value().to_string(),
                    reason: reason.as_str().to_string(),
                    candidates: value
                        .candidates()
                        .iter()
                        .map(|(v, l)| format!("{l} ({v})"))
                        .collect(),
                });
            }
            out.push(value.value().to_string());
        }
    }
    Ok((resolved, unverified))
}

/// The in-band warning lines for unverified filters (Markdown and terminal output).
pub fn unverified_filter_notes(table: &str, filters: &[UnverifiedFilter], empty: bool) -> String {
    let mut out = String::new();
    for f in filters {
        let known = if f.candidates.is_empty() {
            String::new()
        } else {
            format!(
                " Known values: {}.",
                crate::untrusted::inline(&f.candidates.join(", "))
            )
        };
        out.push_str(&format!(
            "⚠ {} \"{}\" could not be verified for {table} ({}); results may be incomplete or empty.{known}\n",
            f.field,
            crate::untrusted::inline(&f.input),
            f.reason
        ));
    }
    if empty && !filters.is_empty() {
        out.push_str("0 results; the filter above could not be verified.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{PackOrigin, ootb_file, parse_pack};
    use serde_json::json;

    const USER_PACK: &str = r#"schema_version = 1
pack_version = "1"
name = "example-corp"
instances = ["example.service-now.com"]
[choices.incident.priority]
values = [
  { value = "0", label = "0 - Emergency" },
  { value = "1", label = "1 - Critical" },
  { value = "2", label = "2 - High" },
  { value = "3", label = "3 - Moderate" },
  { value = "4", label = "4 - Minor", aliases = ["p4", "minor"] },
  { value = "5", label = "5 - Low", aliases = ["p5", "low"] },
]
"#;

    fn pack(user: Option<&str>) -> MergedPack {
        let ootb = ootb_file();
        let file = user.map(|t| parse_pack(t).expect("parse"));
        let mut layers = vec![(PackOrigin::Ootb, &ootb, None)];
        if let Some(f) = &file {
            layers.push((PackOrigin::Profile, f, None));
        }
        MergedPack::from_layers(&layers)
    }

    fn schema(choices: &[(&str, &str)]) -> CachedTableSchema {
        let mut s = CachedTableSchema {
            table: "incident".to_string(),
            super_class: Some("task".to_string()),
            fields: BTreeMap::new(),
            choices: BTreeMap::new(),
            loaded_from_cache: false,
        };
        if !choices.is_empty() {
            s.choices.insert(
                "priority".to_string(),
                choices
                    .iter()
                    .map(|(v, l)| CachedChoice {
                        value: (*v).to_string(),
                        label: (*l).to_string(),
                        sequence: None,
                    })
                    .collect(),
            );
        }
        s
    }

    const OOTB_PRIORITIES: &[(&str, &str)] = &[
        ("1", "1 - Critical"),
        ("2", "2 - High"),
        ("3", "3 - Moderate"),
        ("4", "4 - Low"),
        ("5", "5 - Planning"),
    ];
    const RENUMBERED: &[(&str, &str)] = &[
        ("0", "0 - Emergency"),
        ("1", "1 - Critical"),
        ("2", "2 - High"),
        ("3", "3 - Moderate"),
        ("4", "4 - Minor"),
        ("5", "5 - Low"),
    ];

    fn resolve(
        p: &MergedPack,
        s: &CachedTableSchema,
        input: &str,
    ) -> Result<ResolvedValue, SncfrError> {
        let ctx = ResolveCtx {
            pack: p,
            table: "incident",
            schema: s,
            sample: None,
            discovered: None,
        };
        resolve_choice(&ctx, "priority", input)
    }

    #[test]
    fn row1_user_pack_alias_resolves_with_source_pack() {
        // CT-07
        let r = resolve(&pack(Some(USER_PACK)), &schema(&[]), "low").expect("resolve");
        assert_eq!(
            (r.value(), r.label(), r.source()),
            ("5", Some("5 - Low"), Some(ValueSource::Pack))
        );
        assert_eq!(r.status_label(), "verified");
    }

    #[test]
    fn row2_user_pack_without_the_input_is_exit_2_listing_pack_values() {
        // CT-07b
        let text = USER_PACK.replace(", aliases = [\"p5\", \"low\"]", "");
        let err = resolve(&pack(Some(&text)), &schema(&[]), "low").unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        let SncfrError::Validation { valid_choices, .. } = err else {
            panic!()
        };
        assert_eq!(valid_choices[0], "5 - Low (5)", "suggestion first");
        assert_eq!(valid_choices.len(), 6);
    }

    #[test]
    fn row3_ootb_alias_confirmed_by_readable_ootb_instance() {
        // CT-07c
        let r = resolve(&pack(None), &schema(OOTB_PRIORITIES), "low").expect("resolve");
        assert_eq!((r.value(), r.source()), ("4", Some(ValueSource::Ootb)));
    }

    #[test]
    fn row4_renumbered_readable_instance_rejects_unconfirmed_alias() {
        // CT-07d: ootb's `low -> 4 "4 - Low"` is not confirmed by "4 - Minor".
        let err = resolve(&pack(None), &schema(RENUMBERED), "low").unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        let SncfrError::Validation { valid_choices, .. } = err else {
            panic!()
        };
        assert_eq!(valid_choices[0], "5 - Low (5)");
    }

    #[test]
    fn row7_no_metadata_is_unverifiable_with_the_literal_value() {
        // CT-08d
        let r = resolve(&pack(None), &schema(&[]), "low").expect("resolve");
        assert_eq!(r.unverifiable(), Some(UnverifiableReason::NoMetadata));
        assert_eq!(r.value(), "low");
        assert_eq!(r.display(), "UNVERIFIABLE");
        assert_eq!(r.status_label(), "UNVERIFIABLE (no_metadata)");
    }

    #[test]
    fn row9_pack_contradicting_instance_is_unverifiable_unless_workaround() {
        // CT-09b (resolution half)
        let conflict: &[(&str, &str)] = &[("5", "5 - Planning")];
        let r = resolve(&pack(Some(USER_PACK)), &schema(conflict), "low").expect("resolve");
        assert_eq!(r.unverifiable(), Some(UnverifiableReason::PackConflict));
        assert_eq!(r.value(), "5");
        let workaround = USER_PACK.replace(
            "[choices.incident.priority]\n",
            "[choices.incident.priority]\nworkaround = true\n",
        );
        let r = resolve(&pack(Some(&workaround)), &schema(conflict), "low").expect("resolve");
        assert_eq!(r.source(), Some(ValueSource::Pack));
    }

    #[test]
    fn row10_draft_pack_values_are_unverifiable() {
        // CT-35b (resolution half)
        let draft = USER_PACK.replace(
            "name = \"example-corp\"",
            "name = \"example-corp\"\nstatus = \"draft\"",
        );
        let r = resolve(&pack(Some(&draft)), &schema(&[]), "low").expect("resolve");
        assert_eq!(r.unverifiable(), Some(UnverifiableReason::DraftPack));
        assert_eq!(r.value(), "5");
    }

    #[test]
    fn numeric_input_echoes_its_label() {
        // CT-09 (SAFE-6)
        let r = resolve(&pack(Some(USER_PACK)), &schema(&[]), "4").expect("resolve");
        assert_eq!(r.label(), Some("4 - Minor"));
        let r = resolve(&pack(None), &schema(&[]), "4").expect("resolve");
        assert_eq!(r.display(), "UNVERIFIABLE");
    }

    #[test]
    fn duplicate_instance_labels_are_ambiguous() {
        // CT-13 (SAFE-5)
        let dup: &[(&str, &str)] = &[("4", "Low"), ("5", "Low")];
        let err = resolve(&pack(None), &schema(dup), "low").unwrap_err();
        let SncfrError::Validation {
            valid_choices,
            message,
            ..
        } = err
        else {
            panic!()
        };
        assert!(message.contains("more than one"));
        assert_eq!(valid_choices.len(), 2);
    }

    #[test]
    fn cached_sets_report_cache_as_source() {
        let mut s = schema(OOTB_PRIORITIES);
        s.loaded_from_cache = true;
        let r = resolve(&pack(None), &s, "2 - High").expect("resolve");
        assert_eq!(r.source(), Some(ValueSource::Cache));
    }

    #[test]
    fn task_level_filters_must_mean_the_same_on_every_child_table() {
        // CT-17 (Q-1)
        let p = pack(None);
        let mk = |table: &str, rows: &[(&str, &str)]| {
            let mut s = schema(&[]);
            s.table = table.to_string();
            s.choices.insert(
                "state".to_string(),
                rows.iter()
                    .map(|(v, l)| CachedChoice {
                        value: (*v).to_string(),
                        label: (*l).to_string(),
                        sequence: None,
                    })
                    .collect(),
            );
            (table.to_string(), s)
        };
        let diverging = [
            mk("incident", &[("6", "Resolved")]),
            mk("sc_req_item", &[("3", "Closed Complete")]),
        ];
        let err = resolve_across_children(&p, "state", "Resolved", &diverging).unwrap_err();
        let SncfrError::Validation { valid_choices, .. } = err else {
            panic!()
        };
        assert!(valid_choices.iter().any(|c| c == "incident: Resolved (6)"));
        assert!(
            valid_choices
                .iter()
                .any(|c| c == "sc_req_item: no such value")
        );

        let agreeing = [
            mk("incident", &[("6", "Resolved")]),
            mk("problem", &[("6", "Resolved")]),
        ];
        let v = resolve_across_children(&p, "state", "resolved", &agreeing)
            .unwrap()
            .expect("value");
        assert_eq!(v.value(), "6");
        assert!(
            resolve_across_children(&p, "state", "x", &[])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn field_typing_fails_closed_for_unknown_fields_and_types() {
        // CT-10 / CT-18 (resolution half)
        let p = pack(None);
        let s = schema(&[]);
        let record = json!({
            "u_tier": { "value": "", "display_value": "" },
            "short_description": { "value": "x", "display_value": "x" },
            "u_level": { "value": "2", "display_value": "Two" },
        });
        let ctx = ResolveCtx {
            pack: &p,
            table: "incident",
            schema: &s,
            sample: Some(&record),
            discovered: None,
        };
        let r = resolve_field(&ctx, "u_tier", "gold").expect("resolve");
        assert_eq!(r.unverifiable(), Some(UnverifiableReason::UnknownFieldType));
        let r = resolve_field(&ctx, "u_teir", "gold").expect("resolve");
        assert_eq!(r.unverifiable(), Some(UnverifiableReason::UnknownField));
        let r = resolve_field(&ctx, "short_description", "VPN down").expect("resolve");
        assert!(r.is_free_text());
        assert_eq!(r.status_label(), "n/a (free text)");
        assert_eq!(ctx.classify("u_level"), FieldType::Choice);
        assert!(matches!(
            ctx.classify("assignment_group"),
            FieldType::Reference { .. }
        ));
    }

    #[test]
    fn sampled_links_type_references_with_their_table() {
        // DISC-1: with sys_dictionary unreadable, a `link` names the reference table when the
        // table passes the table-name rule; otherwise the field is a reference of unknown table.
        let p = pack(None);
        let s = schema(&[]);
        let record = json!({
            "u_service": { "value": "a".repeat(32), "display_value": "Mail",
                "link": format!("https://x.service-now.com/api/now/table/cmdb_ci_service/{}", "a".repeat(32)) },
            "u_odd": { "value": "1", "display_value": "One",
                "link": "https://x.service-now.com/api/now/table/Bad-Table/1" },
        });
        let ctx = ResolveCtx {
            pack: &p,
            table: "incident",
            schema: &s,
            sample: Some(&record),
            discovered: None,
        };
        assert_eq!(
            ctx.classify("u_service"),
            FieldType::Reference {
                table: Some("cmdb_ci_service".to_string())
            }
        );
        assert_eq!(ctx.classify("u_odd"), FieldType::Reference { table: None });
    }

    #[test]
    fn in_use_sets_parse_labels_and_skip_non_choice_types() {
        // DISC-2 scope: only Choice-typed listed fields are probed.
        let resp = json!({ "result": [
            { "stats": { "count": "4" }, "groupby_fields": [{ "field": "priority", "value": "5", "display_value": "5 - Low" }] },
            { "stats": { "count": "1" }, "groupby_fields": [{ "field": "priority", "value": "", "display_value": "" }] },
            { "stats": { "count": "2" }, "groupby_fields": [{ "field": "priority", "value": "2" }] },
        ]});
        let set = parse_in_use(&resp, "priority");
        assert_eq!(
            pairs(&set),
            vec![
                ("5".to_string(), "5 - Low".to_string()),
                ("2".to_string(), "2".to_string())
            ]
        );

        let p = pack(None);
        let mut s = schema(&[]);
        s.fields.insert(
            "close_code".to_string(),
            crate::cache::CachedFieldMeta {
                label: "Resolution code".to_string(),
                internal_type: "string".to_string(),
                mandatory: false,
                max_length: None,
                reference_table: None,
                is_custom: false,
            },
        );
        let ctx = ResolveCtx {
            pack: &p,
            table: "incident",
            schema: &s,
            sample: None,
            discovered: None,
        };
        assert!(ctx.wants_discovery("priority"));
        assert!(
            !ctx.wants_discovery("close_code"),
            "string-typed: not probed"
        );
        assert!(!ctx.wants_discovery("assigned_to"), "reference: not probed");
        assert!(!ctx.wants_discovery("u_tier"), "not listed");
    }
}
