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
    /// In-use sets from the Aggregate API (DISC-2), keyed by field. `None` until discovery lands.
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
            Some("inferred_reference") => return FieldType::Reference { table: None },
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
            if sample.get(field).and_then(|v| v.get("link")).is_some() {
                return FieldType::Reference { table: None };
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

    // 3. In-use (discovered) set — filled in by DISC-2; `None` until then.
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
        // CT-08d (and row 5's interim outcome until discovery lands)
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
}
