//! Per-instance capability record (CAP-1, ADR-0003 amendment).
//!
//! What sncfr has learned about an instance's REST surface is persisted in
//! `capabilities.json` instead of being assumed or re-probed on every run. Precedence: a
//! non-expired observation (or `doctor --refresh` probe) beats a pack seed, which beats
//! `Unknown`. Only an HTTP status and a closed [`CapHint`] are stored, never response text.

use crate::cache::InstanceCache;
use crate::pack::MergedPack;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// How long one observation stays authoritative.
pub const OBSERVATION_TTL_DAYS: i64 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    BatchApi,
    CatalogApi,
    ChoiceTableFilter,
    DictionaryReadable,
    NumberTableReadable,
    StatsGroupBy,
}

impl Capability {
    pub const ALL: [Self; 6] = [
        Self::BatchApi,
        Self::CatalogApi,
        Self::ChoiceTableFilter,
        Self::DictionaryReadable,
        Self::NumberTableReadable,
        Self::StatsGroupBy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BatchApi => "batch_api",
            Self::CatalogApi => "catalog_api",
            Self::ChoiceTableFilter => "choice_table_filter",
            Self::DictionaryReadable => "dictionary_readable",
            Self::NumberTableReadable => "number_table_readable",
            Self::StatsGroupBy => "stats_group_by",
        }
    }

    fn seed(self, pack: &MergedPack) -> Option<bool> {
        let s = &pack.capabilities;
        match self {
            Self::BatchApi => s.batch_api,
            Self::CatalogApi => s.catalog_api,
            Self::ChoiceTableFilter => s.choice_table_filter,
            Self::DictionaryReadable => s.dictionary_readable,
            Self::NumberTableReadable => s.number_table_readable,
            Self::StatsGroupBy => s.stats_group_by,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapState {
    Available,
    Unavailable,
    Unauthorized,
    Unknown,
}

impl CapState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Unauthorized => "unauthorized",
            Self::Unknown => "unknown",
        }
    }

    /// Whether sncfr should still try the capability (`Available` or `Unknown`).
    pub const fn worth_trying(self) -> bool {
        matches!(self, Self::Available | Self::Unknown)
    }
}

/// The only detail persisted about a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapHint {
    InvalidTable,
    UriNotResource,
    Acl,
    Timeout,
    ZeroRows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapSource {
    Pack,
    Observed,
    Probe,
}

impl CapSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Observed => "observed",
            Self::Probe => "probe",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapObservation {
    pub state: CapState,
    pub source: CapSource,
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<CapHint>,
}

/// One capability's effective state, as reported by `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapStatus {
    pub capability: String,
    pub state: CapState,
    /// `pack`, `observed`, `probe`, or `none`.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<CapHint>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRecord {
    #[serde(default)]
    pub observations: BTreeMap<Capability, CapObservation>,
}

fn record_path() -> PathBuf {
    PathBuf::from("capabilities.json")
}

impl CapabilityRecord {
    /// Loads the record, dropping observations older than [`OBSERVATION_TTL_DAYS`].
    pub fn load(cache: &InstanceCache) -> Self {
        let mut rec: Self = cache
            .read_allow_stale::<Self>(&record_path())
            .ok()
            .flatten()
            .map(|(rec, _stale)| rec)
            .unwrap_or_default();
        let cutoff = Utc::now() - Duration::days(OBSERVATION_TTL_DAYS);
        rec.observations.retain(|_, o| o.observed_at > cutoff);
        rec
    }

    /// Effective state: observation (or probe) > pack seed (`true` → Available, `false` →
    /// Unavailable) > Unknown.
    pub fn effective(&self, cap: Capability, pack: &MergedPack) -> (CapState, Option<CapSource>) {
        if let Some(o) = self.observations.get(&cap) {
            return (o.state, Some(o.source));
        }
        match cap.seed(pack) {
            Some(true) => (CapState::Available, Some(CapSource::Pack)),
            Some(false) => (CapState::Unavailable, Some(CapSource::Pack)),
            None => (CapState::Unknown, None),
        }
    }

    /// Every capability's effective state, for `doctor`.
    pub fn statuses(&self, pack: &MergedPack) -> Vec<CapStatus> {
        let now = Utc::now();
        Capability::ALL
            .iter()
            .map(|cap| {
                let (state, source) = self.effective(*cap, pack);
                let obs = self.observations.get(cap);
                CapStatus {
                    capability: cap.as_str().to_string(),
                    state,
                    source: source.map_or("none", CapSource::as_str).to_string(),
                    age_secs: obs.map(|o| (now - o.observed_at).num_seconds()),
                    http_status: obs.and_then(|o| o.http_status),
                    hint: obs.and_then(|o| o.hint),
                }
            })
            .collect()
    }

    /// Records one observation (read-modify-write; the cache writes atomically, last writer wins).
    pub fn observe(
        cache: &InstanceCache,
        cap: Capability,
        state: CapState,
        source: CapSource,
        http_status: Option<u16>,
        hint: Option<CapHint>,
    ) {
        let mut rec = Self::load(cache);
        rec.observations.insert(
            cap,
            CapObservation {
                state,
                source,
                observed_at: Utc::now(),
                http_status,
                hint,
            },
        );
        crate::debug_log!(
            "capabilities",
            "{} = {} ({})",
            cap.as_str(),
            state.as_str(),
            source.as_str()
        );
        // The file-level TTL is long; each observation carries its own age.
        let _ = cache.write_entry(&record_path(), &rec, 30 * 24 * 60 * 60);
    }

    /// Forgets every observation (`doctor --refresh` before re-probing).
    pub fn clear(cache: &InstanceCache) {
        let _ = cache.write_entry(&record_path(), &Self::default(), 30 * 24 * 60 * 60);
    }
}

/// Convenience: the effective state of `cap` for this instance under the active pack.
pub fn state(cache: &InstanceCache, cap: Capability) -> CapState {
    CapabilityRecord::load(cache)
        .effective(cap, crate::pack::active())
        .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{PackOrigin, ootb_file, parse_pack};
    use tempfile::tempdir;

    fn pack_with_seed(seed: &str) -> MergedPack {
        let ootb = ootb_file();
        let user = parse_pack(&format!(
            "schema_version = 1\npack_version = \"1\"\nname = \"t\"\ninstances = [\"x\"]\n[capabilities]\n{seed}\n"
        ))
        .expect("parse");
        MergedPack::from_layers(&[
            (PackOrigin::Ootb, &ootb, None),
            (PackOrigin::Profile, &user, None),
        ])
    }

    #[test]
    fn observation_beats_seed_beats_unknown() {
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let pack = pack_with_seed("batch_api = false\ncatalog_api = true");
        let rec = CapabilityRecord::load(&cache);
        assert_eq!(
            rec.effective(Capability::BatchApi, &pack),
            (CapState::Unavailable, Some(CapSource::Pack))
        );
        assert_eq!(
            rec.effective(Capability::CatalogApi, &pack),
            (CapState::Available, Some(CapSource::Pack))
        );
        assert_eq!(
            rec.effective(Capability::StatsGroupBy, &pack),
            (CapState::Unknown, None)
        );

        CapabilityRecord::observe(
            &cache,
            Capability::BatchApi,
            CapState::Available,
            CapSource::Observed,
            Some(200),
            None,
        );
        let rec = CapabilityRecord::load(&cache);
        assert_eq!(
            rec.effective(Capability::BatchApi, &pack),
            (CapState::Available, Some(CapSource::Observed))
        );
    }

    #[test]
    fn expired_observations_are_dropped_and_no_text_is_persisted() {
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        CapabilityRecord::observe(
            &cache,
            Capability::BatchApi,
            CapState::Unavailable,
            CapSource::Observed,
            Some(400),
            Some(CapHint::UriNotResource),
        );
        let raw = std::fs::read_to_string(dir.path().join("capabilities.json")).expect("file");
        assert!(raw.contains("uri_not_resource"));
        assert!(
            !raw.to_lowercase().contains("does not represent"),
            "no response text: {raw}"
        );

        let mut rec = CapabilityRecord::load(&cache);
        rec.observations
            .get_mut(&Capability::BatchApi)
            .expect("obs")
            .observed_at = Utc::now() - Duration::days(OBSERVATION_TTL_DAYS + 1);
        let _ = cache.write_entry(&record_path(), &rec, 3600);
        assert!(CapabilityRecord::load(&cache).observations.is_empty());
    }

    #[test]
    fn statuses_cover_every_capability() {
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let s = CapabilityRecord::load(&cache).statuses(crate::pack::active());
        assert_eq!(s.len(), Capability::ALL.len());
        assert!(
            s.iter()
                .all(|c| c.state == CapState::Unknown && c.source == "none")
        );
    }
}
