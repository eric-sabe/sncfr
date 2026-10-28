//! The merged, read-only view of all pack layers that the rest of sncfr consumes.

use super::schema::{
    CapabilitiesSeed, CatalogSection, ChoiceSetFile, DefaultFields, GroupsSection, PackFile,
    PackStatus, RecipeFile, RuleFile, TriageSection,
};
use serde::Serialize;
use std::collections::BTreeMap;

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
        }
    }

    /// Builds the merged view from layers in precedence order (ootb first).
    pub fn from_layers(layers: &[(PackOrigin, &PackFile, Option<String>)]) -> Self {
        let mut merged = Self::empty();
        for (origin, file, path) in layers {
            merged.apply_layer(*origin, file, path.clone());
        }
        merged
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
                (&core.known_free_text, &mut c.known_free_text),
            ];
            for (src, dst) in lists {
                if let Some(v) = src {
                    dst.clone_from(v);
                }
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
