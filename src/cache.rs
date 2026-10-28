use crate::error::SncfrError;
use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Default TTL for `identity.json` (`@me` user and group memberships): 24 hours.
pub const DEFAULT_IDENTITY_TTL_SECS: u64 = 24 * 60 * 60;

/// Default TTL for `prefixes.json` (`sys_number` prefix -> table mapping): 7 days.
pub const DEFAULT_PREFIXES_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Default TTL for `schemas/<table>.json` (`sys_dictionary` & `sys_choice`): 24 hours.
pub const DEFAULT_SCHEMA_TTL_SECS: u64 = 24 * 60 * 60;

/// Envelope wrapping any cached artifact on disk with fetch timestamp and TTL metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub fetched_at: DateTime<Utc>,
    pub ttl_seconds: u64,
    pub data: T,
}

impl<T> CacheEntry<T> {
    /// Creates a new [`CacheEntry`] stamped with the current UTC time.
    pub fn new(data: T, ttl_seconds: u64) -> Self {
        Self {
            fetched_at: Utc::now(),
            ttl_seconds,
            data,
        }
    }

    /// Returns `true` if this entry's TTL has elapsed as of `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        let ttl = Duration::seconds(self.ttl_seconds.min(i64::MAX as u64) as i64);
        now >= self.fetched_at + ttl
    }
}

/// Cached `@me` user and group identity (`~/.cache/sncfr/<instance>/identity.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedIdentity {
    pub sys_id: String,
    pub user_name: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<CachedGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedGroup {
    pub sys_id: String,
    pub name: String,
}

/// Cached `sys_number` prefix-to-table mappings (`~/.cache/sncfr/<instance>/prefixes.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedPrefixes {
    /// Uppercase ticket prefix (e.g., `"INC"`) -> table name (e.g., `"incident"`). On disk this
    /// is what `sys_number` returned; in memory it is the effective map (see
    /// `resolve::effective_prefixes`).
    pub prefixes: BTreeMap<String, String>,
    /// Prefixes learned from the `task` fallback (ID-3). Kept across `sys_number` resyncs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub learned: BTreeMap<String, String>,
}

/// Cached table dictionary and choice options (`~/.cache/sncfr/<instance>/schemas/<table>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedTableSchema {
    pub table: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_class: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, CachedFieldMeta>,
    #[serde(default)]
    pub choices: BTreeMap<String, Vec<CachedChoice>>,
    /// Set when this schema came from `schemas/<table>.json` rather than a live fetch, so
    /// previews can report `cache` vs `sys_choice` (SAFE-2). Never persisted.
    #[serde(skip)]
    pub loaded_from_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedFieldMeta {
    pub label: String,
    pub internal_type: String,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_table: Option<String>,
    /// True if field starts with `u_` or `x_`.
    #[serde(default)]
    pub is_custom: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedChoice {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub sequence: Option<i32>,
}

/// Manages the local per-instance metadata cache directory (`~/.cache/sncfr/<instance>/`).
#[derive(Debug, Clone)]
pub struct InstanceCache {
    instance_dir: PathBuf,
}

impl InstanceCache {
    /// Resolves the cache directory for `instance_key` using `SNCFR_CACHE_DIR` or `~/.cache/sncfr/<instance_key>`.
    pub fn for_instance(instance_key: &str) -> Result<Self, SncfrError> {
        let base_cache = if let Ok(custom) = std::env::var("SNCFR_CACHE_DIR")
            && !custom.trim().is_empty()
        {
            PathBuf::from(custom)
        } else {
            let base_dirs =
                directories::BaseDirs::new().ok_or_else(|| SncfrError::InvalidArgs {
                    message: "Unable to determine user home directory for metadata cache"
                        .to_string(),
                    remediation: Some("Set `SNCFR_CACHE_DIR=/path/to/cache`.".to_string()),
                })?;
            base_dirs.home_dir().join(".cache").join("sncfr")
        };

        Ok(Self::with_instance_dir(
            base_cache.join(sanitize_filename(instance_key)),
        ))
    }

    /// Creates an [`InstanceCache`] rooted at an explicit directory path.
    pub fn with_instance_dir(instance_dir: PathBuf) -> Self {
        Self { instance_dir }
    }

    /// Returns the root directory for this instance's cache.
    pub fn dir(&self) -> &Path {
        &self.instance_dir
    }

    /// Reads a cached entry at `rel_path`, returning `Ok(None)` if missing or expired.
    pub fn read_fresh<T: DeserializeOwned>(
        &self,
        rel_path: &Path,
    ) -> Result<Option<T>, SncfrError> {
        match self.read_allow_stale(rel_path)? {
            Some((data, false)) => Ok(Some(data)),
            Some((_, true)) | None => Ok(None),
        }
    }

    /// Reads a cached entry at `rel_path`, returning `Ok(Some((data, is_expired)))` even if the TTL has elapsed.
    pub fn read_allow_stale<T: DeserializeOwned>(
        &self,
        rel_path: &Path,
    ) -> Result<Option<(T, bool)>, SncfrError> {
        let full_path = self.instance_dir.join(rel_path);
        if !full_path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&full_path).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to read cache file '{}': {e}", full_path.display()),
            remediation: None,
        })?;
        let entry: CacheEntry<T> = match serde_json::from_str(&raw) {
            Ok(entry) => entry,
            Err(_) => {
                // Corrupt or incompatible cache file: treat as cache miss so caller re-fetches cleanly.
                return Ok(None);
            }
        };
        let is_expired = entry.is_expired_at(Utc::now());
        Ok(Some((entry.data, is_expired)))
    }

    /// Atomically writes a [`CacheEntry<T>`] to `rel_path` inside the instance cache directory.
    pub fn write_entry<T: Serialize>(
        &self,
        rel_path: &Path,
        data: &T,
        ttl_seconds: u64,
    ) -> Result<(), SncfrError> {
        let full_path = self.instance_dir.join(rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|e| SncfrError::InvalidArgs {
                message: format!(
                    "Failed to create cache directory '{}': {e}",
                    parent.display()
                ),
                remediation: None,
            })?;
        }

        let entry = CacheEntry::new(data, ttl_seconds);
        let serialized =
            serde_json::to_string_pretty(&entry).map_err(|e| SncfrError::InvalidArgs {
                message: format!("Failed to serialize cache entry: {e}"),
                remediation: None,
            })?;

        let tmp_path = full_path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp_path, serialized).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to write cache temp file '{}': {e}",
                tmp_path.display()
            ),
            remediation: None,
        })?;
        fs::rename(&tmp_path, &full_path).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to finalize cache file '{}': {e}",
                full_path.display()
            ),
            remediation: None,
        })?;
        Ok(())
    }

    /// Reads fresh `@me` [`CachedIdentity`] (`identity.json`).
    pub fn read_identity(&self) -> Result<Option<CachedIdentity>, SncfrError> {
        self.read_fresh(Path::new("identity.json"))
    }

    /// Writes `@me` [`CachedIdentity`] (`identity.json`) with default 24h TTL.
    pub fn write_identity(&self, identity: &CachedIdentity) -> Result<(), SncfrError> {
        self.write_entry(
            Path::new("identity.json"),
            identity,
            DEFAULT_IDENTITY_TTL_SECS,
        )
    }

    /// Reads fresh [`CachedPrefixes`] (`prefixes.json`).
    pub fn read_prefixes(&self) -> Result<Option<CachedPrefixes>, SncfrError> {
        self.read_fresh(Path::new("prefixes.json"))
    }

    /// Writes [`CachedPrefixes`] (`prefixes.json`) with default 7d TTL.
    pub fn write_prefixes(&self, prefixes: &CachedPrefixes) -> Result<(), SncfrError> {
        self.write_entry(
            Path::new("prefixes.json"),
            prefixes,
            DEFAULT_PREFIXES_TTL_SECS,
        )
    }

    /// Reads fresh [`CachedTableSchema`] (`schemas/<table>.json`).
    pub fn read_table_schema(&self, table: &str) -> Result<Option<CachedTableSchema>, SncfrError> {
        let rel = PathBuf::from("schemas").join(format!("{}.json", sanitize_filename(table)));
        self.read_fresh(&rel)
    }

    /// Writes [`CachedTableSchema`] (`schemas/<table>.json`) with default 24h TTL.
    pub fn write_table_schema(&self, schema: &CachedTableSchema) -> Result<(), SncfrError> {
        let rel =
            PathBuf::from("schemas").join(format!("{}.json", sanitize_filename(&schema.table)));
        self.write_entry(&rel, schema, DEFAULT_SCHEMA_TTL_SECS)
    }
}

fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrips_identity_prefixes_and_schema_with_ttl() {
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());

        let identity = CachedIdentity {
            sys_id: "6816f79cc0a8016401c5a33be04be441".to_string(),
            user_name: "jane.doe".to_string(),
            display_name: "Jane Doe".to_string(),
            email: Some("jane.doe@example.com".to_string()),
            groups: vec![CachedGroup {
                sys_id: "g123".to_string(),
                name: "Cloud Platform".to_string(),
            }],
        };
        cache.write_identity(&identity).expect("write identity");
        assert_eq!(
            cache.read_identity().expect("read identity"),
            Some(identity)
        );

        let mut prefixes = CachedPrefixes::default();
        prefixes
            .prefixes
            .insert("INC".to_string(), "incident".to_string());
        cache.write_prefixes(&prefixes).expect("write prefixes");
        assert_eq!(
            cache.read_prefixes().expect("read prefixes"),
            Some(prefixes)
        );

        let mut schema = CachedTableSchema {
            table: "incident".to_string(),
            super_class: Some("task".to_string()),
            fields: BTreeMap::new(),
            choices: BTreeMap::new(),
            loaded_from_cache: false,
        };
        schema.choices.insert(
            "state".to_string(),
            vec![CachedChoice {
                label: "In Progress".to_string(),
                value: "2".to_string(),
                sequence: Some(2),
            }],
        );
        cache
            .write_table_schema(&schema)
            .expect("write table schema");
        assert_eq!(
            cache
                .read_table_schema("incident")
                .expect("read table schema"),
            Some(schema)
        );
    }

    #[test]
    fn expired_entry_returns_none_on_read_fresh_and_some_on_allow_stale() {
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let rel = Path::new("identity.json");

        let identity = CachedIdentity {
            sys_id: "u1".to_string(),
            user_name: "user1".to_string(),
            display_name: "User One".to_string(),
            email: None,
            groups: vec![],
        };
        // Write with TTL = 0 seconds so it is immediately expired
        cache
            .write_entry(rel, &identity, 0)
            .expect("write expired entry");

        assert_eq!(
            cache
                .read_fresh::<CachedIdentity>(rel)
                .expect("read_fresh expired"),
            None
        );

        let (stale_data, is_expired) = cache
            .read_allow_stale::<CachedIdentity>(rel)
            .expect("read_allow_stale")
            .expect("entry present");
        assert!(is_expired);
        assert_eq!(stale_data, identity);
    }
}
