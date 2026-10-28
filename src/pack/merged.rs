//! The merged, read-only view of all pack layers that the rest of sncfr consumes.

use super::schema::{
    CapabilitiesSeed, CatalogSection, ChoiceSetFile, DefaultFields, GroupsSection, PackFile,
    PackStatus, RecipeFile, RuleFile, TriageSection,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Which layer an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackOrigin {
    /// The bundled `ootb` pack.
    Ootb,
    /// The profile's `pack = "<path>"`.
    Profile,
    /// `--pack` / `SNCFR_PACK`.
    Override,
}

impl PackOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ootb => "ootb",
            Self::Profile => "profile",
            Self::Override => "override",
        }
    }
}

/// A merged entry tagged with the layer it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sourced<T> {
    pub value: T,
    pub origin: PackOrigin,
}

/// Built-in defaults formerly held in constants (`[core]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CoreDefaults {
    pub probe_tables: Vec<String>,
    pub list_columns: Vec<String>,
    pub dossier_core_fields: Vec<String>,
    pub feed_fields: Vec<String>,
    pub caller_fields: BTreeMap<String, String>,
    pub known_free_text: Vec<String>,
    pub table_aliases: BTreeMap<String, String>,
}

/// Safety-relevant keys, merged as the strictest union of every layer (ADR-0004, NA-4): a later
/// layer can never loosen what an earlier one set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafetyKeys {
    /// `false` if any layer sets `auth.allow_credentials_file = false`.
    pub allow_credentials_file: bool,
    /// The first layer that defines `audit.agent_write_marker` wins; later layers cannot remove it.
    pub agent_write_marker: Option<String>,
    /// The lowest `limits.max_requests_per_minute` of any layer.
    pub max_requests_per_minute: Option<u32>,
    /// Intersection of the `instances` of every user layer that declares any; `None` when no
    /// user layer declares instances (e.g. ootb only).
    pub instances: Option<BTreeSet<String>>,
}

impl Default for SafetyKeys {
    fn default() -> Self {
        Self {
            allow_credentials_file: true,
            agent_write_marker: None,
            max_requests_per_minute: None,
            instances: None,
        }
    }
}

/// A pack entry flagged `workaround = true` (PACK-7), listed by `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Workaround {
    /// e.g. `choices.incident.priority` or `open_rule.incident`.
    pub key: String,
    pub origin: PackOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defect_ref: Option<String>,
}

/// Compact pack identity for `doctor` and `auth status` (PACK-6, PACK-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct PackSummary {
    pub name: String,
    pub pack_version: String,
    pub status: PackStatus,
    pub hash: String,
    pub layers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workarounds: Vec<String>,
}

impl PackSummary {
    /// `<name> <version> · <status> · sha256:<12 hex>`.
    pub fn headline(&self) -> String {
        let status = match self.status {
            PackStatus::Active => "active",
            PackStatus::Draft => "draft",
        };
        format!(
            "{} {} · {status} · {}",
            self.name,
            self.pack_version,
            self.hash.get(..19).unwrap_or(&self.hash)
        )
    }
}

/// One loaded layer, as reported by `pack show` / `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerInfo {
    pub origin: PackOrigin,
    pub name: String,
    pub pack_version: String,
    pub status: PackStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergedPack {
    /// Name of the most specific layer (`ootb` when no user pack is loaded).
    pub name: String,
    pub pack_version: String,
    pub status: PackStatus,
    pub layers: Vec<LayerInfo>,
    pub core: CoreDefaults,
    pub prefixes: BTreeMap<String, Sourced<String>>,
    pub hierarchy: BTreeMap<String, Sourced<String>>,
    /// Keyed `"<table>.<field>"`.
    pub choices: BTreeMap<String, Sourced<ChoiceSetFile>>,
    pub open_rules: BTreeMap<String, Sourced<RuleFile>>,
    pub closed_rules: BTreeMap<String, Sourced<RuleFile>>,
    pub groups: GroupsSection,
    pub fields_default: BTreeMap<String, Sourced<DefaultFields>>,
    pub discovery_choice_fields: BTreeMap<String, Vec<String>>,
    pub recipes: BTreeMap<String, Sourced<RecipeFile>>,
    pub catalog: CatalogSection,
    pub triage: TriageSection,
    pub doctor_absent_tables_ok: Vec<String>,
    pub capabilities: CapabilitiesSeed,
    pub safety: SafetyKeys,
    /// `sha256:<hex>` over the canonical JSON of everything above (PACK-6).
    pub hash: String,
}

impl MergedPack {
    fn empty() -> Self {
        Self {
            name: String::new(),
            pack_version: String::new(),
            status: PackStatus::Active,
            layers: Vec::new(),
            core: CoreDefaults::default(),
            prefixes: BTreeMap::new(),
            hierarchy: BTreeMap::new(),
            choices: BTreeMap::new(),
            open_rules: BTreeMap::new(),
            closed_rules: BTreeMap::new(),
            groups: GroupsSection::default(),
            fields_default: BTreeMap::new(),
            discovery_choice_fields: BTreeMap::new(),
            recipes: BTreeMap::new(),
            catalog: CatalogSection::default(),
            triage: TriageSection::default(),
            doctor_absent_tables_ok: Vec::new(),
            capabilities: CapabilitiesSeed::default(),
            safety: SafetyKeys::default(),
            hash: String::new(),
        }
    }

    /// Builds the merged view from layers in precedence order (ootb first).
    pub fn from_layers(layers: &[(PackOrigin, &PackFile, Option<String>)]) -> Self {
        let mut merged = Self::empty();
        for (origin, file, path) in layers {
            merged.apply_layer(*origin, file, path.clone());
            merged.apply_removals(file);
            merged.apply_safety(*origin, file);
        }
        merged.hash = merged.compute_hash();
        merged
    }

    /// `[remove]`: deletes map keys after the layer that declares it is merged (PACK-3).
    fn apply_removals(&mut self, file: &PackFile) {
        let Some(r) = &file.remove else { return };
        for k in &r.prefixes {
            self.prefixes.remove(&k.to_ascii_uppercase());
        }
        for k in &r.choices {
            self.choices.remove(k);
        }
        for k in &r.open_rule {
            self.open_rules.remove(k);
        }
        for k in &r.closed_rule {
            self.closed_rules.remove(k);
        }
        for k in &r.fields_default {
            self.fields_default.remove(k);
        }
        for k in &r.recipes {
            self.recipes.remove(k);
        }
        self.core
            .probe_tables
            .retain(|t| !r.core_probe_tables.contains(t));
    }

    /// Folds one layer's safety keys in as a strictest union (NA-4).
    fn apply_safety(&mut self, origin: PackOrigin, file: &PackFile) {
        let s = &mut self.safety;
        if file.auth.as_ref().and_then(|a| a.allow_credentials_file) == Some(false) {
            s.allow_credentials_file = false;
        }
        if s.agent_write_marker.is_none() {
            s.agent_write_marker = file
                .audit
                .as_ref()
                .and_then(|a| a.agent_write_marker.clone());
        }
        if let Some(rpm) = file.limits.as_ref().and_then(|l| l.max_requests_per_minute) {
            s.max_requests_per_minute =
                Some(s.max_requests_per_minute.map_or(rpm, |cur| cur.min(rpm)));
        }
        if origin != PackOrigin::Ootb && !file.instances.is_empty() {
            let declared: BTreeSet<String> = file
                .instances
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .collect();
            s.instances = Some(match s.instances.take() {
                Some(cur) => cur.intersection(&declared).cloned().collect(),
                None => declared,
            });
        }
    }

    fn compute_hash(&self) -> String {
        let mut view = self.clone();
        view.hash = String::new();
        let canonical = serde_json::to_vec(&view).unwrap_or_default();
        let digest = Sha256::digest(&canonical);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    pub fn summary(&self) -> PackSummary {
        PackSummary {
            name: self.name.clone(),
            pack_version: self.pack_version.clone(),
            status: self.status,
            hash: self.hash.clone(),
            layers: self
                .layers
                .iter()
                .map(|l| match &l.path {
                    Some(p) => format!("{} ({p})", l.origin.as_str()),
                    None => l.origin.as_str().to_string(),
                })
                .collect(),
            workarounds: self
                .workarounds()
                .into_iter()
                .map(|w| match w.defect_ref {
                    Some(d) => format!("{}: {d}", w.key),
                    None => w.key,
                })
                .collect(),
        }
    }

    /// The merged pack as a single re-loadable pack file (`pack show --toml`).
    pub fn to_pack_file(&self) -> PackFile {
        use super::schema::{
            AuditSection, AuthSection, CoreSection, DiscoverySection, DoctorSection, FieldsSection,
            LimitsSection,
        };
        fn plain<T: Clone>(m: &BTreeMap<String, Sourced<T>>) -> Option<BTreeMap<String, T>> {
            (!m.is_empty()).then(|| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.value.clone()))
                    .collect()
            })
        }
        let mut choices: BTreeMap<String, BTreeMap<String, ChoiceSetFile>> = BTreeMap::new();
        for (key, set) in &self.choices {
            if let Some((table, field)) = key.split_once('.') {
                choices
                    .entry(table.to_string())
                    .or_default()
                    .insert(field.to_string(), set.value.clone());
            }
        }
        let c = &self.core;
        PackFile {
            schema_version: super::schema::SUPPORTED_SCHEMA_VERSION,
            pack_version: self.pack_version.clone(),
            name: self.name.clone(),
            status: self.status,
            instances: self.safety.instances.iter().flatten().cloned().collect(),
            capabilities: Some(self.capabilities.clone()),
            limits: self
                .safety
                .max_requests_per_minute
                .map(|rpm| LimitsSection {
                    max_requests_per_minute: Some(rpm),
                }),
            auth: (!self.safety.allow_credentials_file).then_some(AuthSection {
                allow_credentials_file: Some(false),
            }),
            doctor: (!self.doctor_absent_tables_ok.is_empty()).then(|| DoctorSection {
                extra_probe_tables: Vec::new(),
                absent_tables_ok: self.doctor_absent_tables_ok.clone(),
            }),
            core: Some(CoreSection {
                probe_tables: Some(c.probe_tables.clone()),
                list_columns: Some(c.list_columns.clone()),
                dossier_core_fields: Some(c.dossier_core_fields.clone()),
                feed_fields: Some(c.feed_fields.clone()),
                caller_fields: Some(c.caller_fields.clone()),
                known_free_text: None,
                table_aliases: Some(c.table_aliases.clone()),
            }),
            hierarchy: plain(&self.hierarchy),
            prefixes: plain(&self.prefixes),
            choices: (!choices.is_empty()).then_some(choices),
            open_rule: plain(&self.open_rules),
            closed_rule: plain(&self.closed_rules),
            groups: Some(self.groups.clone()),
            fields: (!self.fields_default.is_empty()).then(|| FieldsSection {
                default: plain(&self.fields_default).unwrap_or_default(),
            }),
            discovery: Some(DiscoverySection {
                choice_fields: self.discovery_choice_fields.clone(),
            }),
            recipes: plain(&self.recipes),
            catalog: Some(self.catalog.clone()),
            audit: self
                .safety
                .agent_write_marker
                .clone()
                .map(|m| AuditSection {
                    agent_write_marker: Some(m),
                }),
            triage: Some(self.triage.clone()),
            remove: None,
        }
    }

    /// `sha256:` plus the first 12 hex characters, for human output.
    pub fn short_hash(&self) -> &str {
        self.hash.get(..19).unwrap_or(&self.hash)
    }

    /// True when the merged pack applies to `instance_host` (always true without user `instances`).
    pub fn binds(&self, instance_host: &str) -> bool {
        self.safety
            .instances
            .as_ref()
            .is_none_or(|set| set.contains(&instance_host.to_ascii_lowercase()))
    }

    /// Every entry flagged `workaround = true` (PACK-7).
    pub fn workarounds(&self) -> Vec<Workaround> {
        let mut out = Vec::new();
        for (k, v) in &self.choices {
            if v.value.workaround {
                out.push(Workaround {
                    key: format!("choices.{k}"),
                    origin: v.origin,
                    defect_ref: v.value.defect_ref.clone(),
                });
            }
        }
        for (section, rules) in [
            ("open_rule", &self.open_rules),
            ("closed_rule", &self.closed_rules),
        ] {
            for (k, v) in rules {
                if v.value.workaround {
                    out.push(Workaround {
                        key: format!("{section}.{k}"),
                        origin: v.origin,
                        defect_ref: v.value.defect_ref.clone(),
                    });
                }
            }
        }
        out
    }

    /// Key-level replace of one layer over the current state (PACK-3).
    fn apply_layer(&mut self, origin: PackOrigin, file: &PackFile, path: Option<String>) {
        fn put<T: Clone>(
            dst: &mut BTreeMap<String, Sourced<T>>,
            src: &BTreeMap<String, T>,
            origin: PackOrigin,
        ) {
            for (k, v) in src {
                dst.insert(
                    k.clone(),
                    Sourced {
                        value: v.clone(),
                        origin,
                    },
                );
            }
        }

        self.name.clone_from(&file.name);
        self.pack_version.clone_from(&file.pack_version);
        self.status = file.status;
        self.layers.push(LayerInfo {
            origin,
            name: file.name.clone(),
            pack_version: file.pack_version.clone(),
            status: file.status,
            path,
        });

        if let Some(core) = &file.core {
            let c = &mut self.core;
            let lists = [
                (&core.probe_tables, &mut c.probe_tables),
                (&core.list_columns, &mut c.list_columns),
                (&core.dossier_core_fields, &mut c.dossier_core_fields),
                (&core.feed_fields, &mut c.feed_fields),
            ];
            for (src, dst) in lists {
                if let Some(v) = src {
                    dst.clone_from(v);
                }
            }
            // Marking a field free text bypasses the write gate, so only ootb may (NA-4).
            if origin == PackOrigin::Ootb
                && let Some(v) = &core.known_free_text
            {
                c.known_free_text.clone_from(v);
            }
            if let Some(v) = &core.caller_fields {
                c.caller_fields.extend(v.clone());
            }
            if let Some(v) = &core.table_aliases {
                c.table_aliases.extend(v.clone());
            }
        }
        if let Some(p) = &file.prefixes {
            let upper: BTreeMap<String, String> = p
                .iter()
                .map(|(k, v)| (k.to_ascii_uppercase(), v.clone()))
                .collect();
            put(&mut self.prefixes, &upper, origin);
        }
        if let Some(h) = &file.hierarchy {
            put(&mut self.hierarchy, h, origin);
        }
        if let Some(tables) = &file.choices {
            for (table, fields) in tables {
                for (field, set) in fields {
                    self.choices.insert(
                        format!("{table}.{field}"),
                        Sourced {
                            value: set.clone(),
                            origin,
                        },
                    );
                }
            }
        }
        if let Some(r) = &file.open_rule {
            put(&mut self.open_rules, r, origin);
        }
        if let Some(r) = &file.closed_rule {
            put(&mut self.closed_rules, r, origin);
        }
        if let Some(g) = &file.groups {
            self.groups = g.clone();
        }
        if let Some(f) = &file.fields {
            put(&mut self.fields_default, &f.default, origin);
        }
        if let Some(d) = &file.discovery {
            self.discovery_choice_fields.extend(d.choice_fields.clone());
        }
        if let Some(r) = &file.recipes {
            put(&mut self.recipes, r, origin);
        }
        if let Some(c) = &file.catalog {
            self.catalog = c.clone();
        }
        if let Some(t) = &file.triage {
            self.triage = t.clone();
        }
        if let Some(d) = &file.doctor {
            self.core
                .probe_tables
                .extend(d.extra_probe_tables.iter().cloned());
            if !d.absent_tables_ok.is_empty() {
                self.doctor_absent_tables_ok.clone_from(&d.absent_tables_ok);
            }
        }
        if let Some(c) = &file.capabilities {
            let seed = &mut self.capabilities;
            let pairs = [
                (c.batch_api, &mut seed.batch_api),
                (c.catalog_api, &mut seed.catalog_api),
                (c.choice_table_filter, &mut seed.choice_table_filter),
                (c.dictionary_readable, &mut seed.dictionary_readable),
                (c.number_table_readable, &mut seed.number_table_readable),
                (c.stats_group_by, &mut seed.stats_group_by),
            ];
            for (src, dst) in pairs {
                if src.is_some() {
                    *dst = src;
                }
            }
        }
    }

    /// Known ticket prefixes (upper-case) → table.
    pub fn prefix_map(&self) -> BTreeMap<String, String> {
        self.prefixes
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect()
    }

    /// Resolves a `--table` shorthand: a ticket prefix (case-insensitive) or a `core.table_aliases`
    /// entry; anything else is taken as a table name.
    pub fn resolve_table_shorthand(&self, table_or_prefix: &str) -> String {
        let trimmed = table_or_prefix.trim();
        if let Some(t) = self.prefixes.get(&trimmed.to_ascii_uppercase()) {
            return t.value.clone();
        }
        let lower = trimmed.to_ascii_lowercase();
        self.core
            .table_aliases
            .get(&lower)
            .cloned()
            .unwrap_or(lower)
    }

    /// The field that holds the "caller" on `table` (`opened_by` when the table isn't listed).
    pub fn caller_field(&self, table: &str) -> &str {
        self.core
            .caller_fields
            .get(table)
            .map_or("opened_by", String::as_str)
    }
}
