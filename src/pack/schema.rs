//! Raw, on-disk Instance Pack schema (ADR-0004, PACK-8).
//!
//! Every struct is `deny_unknown_fields`, so a misspelled or unsupported key anywhere in a pack
//! is an error rather than a silently ignored setting. There is deliberately no `read_only` key
//! at any level: a pack can tighten safety but never loosen it (NA-4).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The only pack schema major version this build understands (PACK-4).
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackStatus {
    /// Reviewed pack; its values may authorize writes.
    #[default]
    Active,
    /// Machine-drafted (`sncfr discover`) pack; values sourced from it are never authoritative.
    Draft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackFile {
    pub schema_version: u32,
    pub pack_version: String,
    pub name: String,
    #[serde(default)]
    pub status: PackStatus,
    /// Instance hosts this pack describes; required for an `active` user pack (NA-14).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CapabilitiesSeed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor: Option<DoctorSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<CoreSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<BTreeMap<String, String>>,
    /// `choices.<table>.<field>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<BTreeMap<String, BTreeMap<String, ChoiceSetFile>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_rule: Option<BTreeMap<String, RuleFile>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_rule: Option<BTreeMap<String, RuleFile>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<GroupsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<FieldsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoverySection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipes: Option<BTreeMap<String, RecipeFile>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage: Option<TriageSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<RemoveSection>,
}

/// Capability seeds: `true` → Available, `false` → Unavailable. Observation overrides (CAP-1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesSeed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_api: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_api: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice_table_filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dictionary_readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number_table_readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_group_by: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_credentials_file: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorSection {
    /// Appended to `core.probe_tables`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_probe_tables: Vec<String>,
    /// Probe tables that may legitimately be missing; reported as "not installed" (CAP-5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub absent_tables_ok: Vec<String>,
}

/// Built-in defaults that used to be constants. `known_free_text` is ootb-only (NA-4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_tables: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_columns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dossier_core_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_fields: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_free_text: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_aliases: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceSetFile {
    pub values: Vec<ChoiceEntryFile>,
    /// Entries apply only when instance metadata confirms the same `(value, label)`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confirm_required: bool,
    /// The set deliberately overrides instance metadata to work around a local defect (PACK-7).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub workaround: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defect_ref: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceEntryFile {
    pub value: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub query: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub workaround: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defect_ref: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffixes: Vec<String>,
    /// Suggestions only; never applied to a payload (SAFE-7).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub suggest_map: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldsSection {
    /// `fields.default.<table>`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub default: BTreeMap<String, DefaultFields>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultFields {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dossier: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySection {
    /// `discovery.choice_fields.<table>`; `task` entries are inherited by task children.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub choice_fields: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    pub steps: Vec<RecipeStep>,
}

/// Read-only recipe steps (WF-2/3). The closed enum is the mutation guard: no variant can carry a
/// method, a body, or a write flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeStep {
    Table {
        id: String,
        table: String,
        #[serde(default)]
        query: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },
    Stats {
        id: String,
        table: String,
        #[serde(default)]
        query: String,
        group_by: String,
    },
    Show {
        id: String,
        ticket: String,
    },
}

impl RecipeStep {
    pub fn id(&self) -> &str {
        match self {
            Self::Table { id, .. } | Self::Stats { id, .. } | Self::Show { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<CatalogPoll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_order_fill: Option<PostOrderFill>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPoll {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wait_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_backoff_ms: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostOrderFill {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_write_marker: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_threshold_pct: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_bucket: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, CustomBucket>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomBucket {
    pub table: String,
    pub query: String,
    pub reason: String,
}

/// Map keys deleted from the merged result after layering (PACK-3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// Entries like `"incident.priority"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_rule: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed_rule: Vec<String>,
    /// Tables whose `fields.default` entry is removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_default: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipes: Vec<String>,
    /// Tables removed from `core.probe_tables`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub core_probe_tables: Vec<String>,
}
