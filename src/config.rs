use crate::cli::Cli;
use crate::error::SncfrError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

/// Authentication method configured for a ServiceNow profile (`docs/SPEC.md` Section 3.1 & 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    /// Corporate SSO via isolated browser `--app` window (CDP) or imported session cookies + `g_ck`.
    #[default]
    Sso,
    /// ServiceNow inbound REST API Key (`x-sn-apikey`).
    #[serde(alias = "api_key")]
    ApiKey,
    /// HTTP Basic authentication (`username` + `password`).
    Basic,
    /// OAuth 2.0 Bearer token.
    Oauth,
}

impl AuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sso => "sso",
            Self::ApiKey => "api-key",
            Self::Basic => "basic",
            Self::Oauth => "oauth",
        }
    }
}

/// Reusable saved ticket view/filter (`[profiles.<name>.views.<view>]` in `config.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedView {
    /// Target table name (defaults to `"task"` when omitted).
    #[serde(default = "default_view_table")]
    pub table: String,
    /// ServiceNow encoded query string (`sysparm_query`).
    pub query: String,
    /// Optional human/agent description of what this view monitors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional custom default columns for `list` when using this view.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

fn default_view_table() -> String {
    "task".to_string()
}

/// Per-instance connection profile (`[profiles.<name>]` in `config.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Target ServiceNow instance URL or shorthand name (e.g., `https://mycompany.service-now.com`).
    pub instance: String,
    /// Authentication method (defaults to `sso`).
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// Optional username hint for `basic` auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Hard-lock this profile to read-only mode (blocks `--write` with exit code 6).
    #[serde(default)]
    pub read_only: bool,
    /// Named saved views (`sncfr list @<view>`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub views: BTreeMap<String, SavedView>,
}

/// Top-level `config.toml` representation (`docs/SPEC.md` Section 7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    /// Default profile name when `--profile` / `SNCFR_PROFILE` is not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Named connection profiles.
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

/// Concrete resolved profile and safety settings for a single CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfile {
    /// Profile name (`"adhoc"` when constructed solely from `--instance` without a config profile).
    pub name: String,
    /// Canonical normalized base URL (e.g., `https://mycompany.service-now.com`).
    pub instance_url: Url,
    /// Hostname used for OS Keychain and cache namespace (e.g., `mycompany.service-now.com` or `127.0.0.1_8080`).
    pub instance_key: String,
    /// Authentication method to use.
    pub auth_method: AuthMethod,
    /// Optional username for Basic auth.
    pub username: Option<String>,
    /// Whether mutations (`--write`) are hard-locked for this invocation, and why.
    pub read_only_lock_reason: Option<String>,
    /// Saved views available on this profile.
    pub views: BTreeMap<String, SavedView>,
}

impl ResolvedProfile {
    /// Returns `true` if a hard read-only lock is active via CLI/env or profile config.
    pub const fn is_read_only_locked(&self) -> bool {
        self.read_only_lock_reason.is_some()
    }

    /// Resolves a `@<view>` (or `<view>`) reference against this profile's saved views.
    pub fn resolve_saved_view(&self, view_ref: &str) -> Result<&SavedView, SncfrError> {
        let key = view_ref.strip_prefix('@').unwrap_or(view_ref);
        self.views.get(key).ok_or_else(|| {
            let available: Vec<String> = self.views.keys().map(|k| format!("@{k}")).collect();
            let remediation = if available.is_empty() {
                format!(
                    "No saved views are defined under `[profiles.{}.views]` in config.toml.",
                    self.name
                )
            } else {
                format!("Available saved views: {}", available.join(", "))
            };
            SncfrError::InvalidArgs {
                message: format!("Unknown saved view '@{key}' on profile '{}'", self.name),
                remediation: Some(remediation),
            }
        })
    }
}

/// Returns the default configuration file path (`SNCFR_CONFIG` or `~/.config/sncfr/config.toml`).
pub fn default_config_path() -> Result<PathBuf, SncfrError> {
    if let Ok(custom) = std::env::var("SNCFR_CONFIG")
        && !custom.trim().is_empty()
    {
        return Ok(PathBuf::from(custom));
    }

    let base_dirs = directories::BaseDirs::new().ok_or_else(|| SncfrError::InvalidArgs {
        message: "Unable to determine user home directory for config.toml".to_string(),
        remediation: Some("Set `SNCFR_CONFIG=/path/to/config.toml` explicitly.".to_string()),
    })?;

    Ok(base_dirs
        .home_dir()
        .join(".config")
        .join("sncfr")
        .join("config.toml"))
}

/// Normalizes a user-supplied ServiceNow instance string into a canonical base [`Url`] and cache/keychain key.
///
/// Accepts:
/// - Full URL: `https://mycompany.service-now.com/` -> `https://mycompany.service-now.com`
/// - Domain without scheme: `mycompany.service-now.com` -> `https://mycompany.service-now.com`
/// - Instance shorthand: `mycompany` -> `https://mycompany.service-now.com`
/// - Localhost HTTP URLs (`http://127.0.0.1:1234` or `http://localhost:1234`) for local wiremock testing.
pub fn normalize_instance_url(raw: &str) -> Result<(Url, String), SncfrError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "Instance URL or hostname cannot be empty".to_string(),
            remediation: Some(
                "Pass `--instance https://<name>.service-now.com` or configure a profile in `~/.config/sncfr/config.toml`."
                    .to_string(),
            ),
        });
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else if trimmed.contains('.')
        || trimmed.starts_with("localhost")
        || trimmed.starts_with("127.0.0.1")
    {
        format!("https://{trimmed}")
    } else {
        format!("https://{trimmed}.service-now.com")
    };

    let mut parsed = Url::parse(&candidate).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Invalid ServiceNow instance URL '{raw}': {e}"),
        remediation: Some(
            "Expected a URL like `https://mycompany.service-now.com` or instance name `mycompany`."
                .to_string(),
        ),
    })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| SncfrError::InvalidArgs {
            message: format!("Instance URL '{raw}' is missing a hostname"),
            remediation: None,
        })?
        .to_lowercase();

    let is_loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    match parsed.scheme() {
        "https" => {}
        "http" if is_loopback => {}
        other => {
            return Err(SncfrError::InvalidArgs {
                message: format!(
                    "Unsupported URL scheme '{other}' for instance '{raw}' (HTTPS is required)"
                ),
                remediation: Some(format!("Use `https://{host}` instead.")),
            });
        }
    }

    // Strip any path, query, or fragment so base URL is strictly scheme://host[:port]
    parsed.set_path("");
    parsed.set_query(None);
    parsed.set_fragment(None);

    let instance_key = match parsed.port() {
        Some(port) => format!("{host}_{port}"),
        None => host,
    };

    Ok((parsed, instance_key))
}

impl AppConfig {
    /// Loads [`AppConfig`] from the default path (`~/.config/sncfr/config.toml` or `SNCFR_CONFIG`).
    /// Returns `Ok(AppConfig::default())` if the file does not exist yet.
    pub fn load_default() -> Result<Self, SncfrError> {
        let path = default_config_path()?;
        Self::load_from_path(&path)
    }

    /// Loads [`AppConfig`] from a specific file path. Returns an empty default config if the file is absent.
    pub fn load_from_path(path: &Path) -> Result<Self, SncfrError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to read config file '{}': {e}", path.display()),
            remediation: None,
        })?;
        toml::from_str(&content).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Invalid TOML in config file '{}': {e}", path.display()),
            remediation: Some(
                "Check `~/.config/sncfr/config.toml` syntax against `docs/SPEC.md` Section 7.1."
                    .to_string(),
            ),
        })
    }

    /// Saves [`AppConfig`] atomically to the specified path, creating parent directories if needed.
    pub fn save_to_path(&self, path: &Path) -> Result<(), SncfrError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| SncfrError::InvalidArgs {
                message: format!(
                    "Failed to create config directory '{}': {e}",
                    parent.display()
                ),
                remediation: None,
            })?;
        }
        let serialized = toml::to_string_pretty(self).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to serialize config to TOML: {e}"),
            remediation: None,
        })?;
        let tmp_path = path.with_extension("toml.tmp");
        fs::write(&tmp_path, serialized).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to write config file '{}': {e}", tmp_path.display()),
            remediation: None,
        })?;
        fs::rename(&tmp_path, path).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to finalize config file '{}': {e}", path.display()),
            remediation: None,
        })?;
        Ok(())
    }

    /// Inserts or updates a profile in `self.profiles` and sets `default_profile` if none was set.
    pub fn upsert_profile(&mut self, name: &str, instance_url: &Url, auth_method: AuthMethod) {
        let target_name = if name == "adhoc" { "default" } else { name };
        let entry = self
            .profiles
            .entry(target_name.to_string())
            .or_insert_with(|| ProfileConfig {
                instance: instance_url.as_str().trim_end_matches('/').to_string(),
                auth_method,
                username: None,
                read_only: false,
                views: BTreeMap::new(),
            });
        entry.instance = instance_url.as_str().trim_end_matches('/').to_string();
        entry.auth_method = auth_method;

        if self.default_profile.is_none() {
            self.default_profile = Some(target_name.to_string());
        }
    }

    /// Resolves the active [`ResolvedProfile`] for the given [`Cli`] flags and config state.
    pub fn resolve_profile(&self, cli: &Cli) -> Result<ResolvedProfile, SncfrError> {
        // Determine target profile name if any exist in config
        let requested_profile_name = cli
            .profile
            .as_deref()
            .or(self.default_profile.as_deref())
            .or_else(|| {
                if self.profiles.contains_key("default") {
                    Some("default")
                } else if self.profiles.len() == 1 {
                    self.profiles.keys().next().map(String::as_str)
                } else {
                    None
                }
            });

        if let Some(profile_name) = requested_profile_name {
            if let Some(profile_cfg) = self.profiles.get(profile_name) {
                let raw_instance = cli.instance.as_deref().unwrap_or(&profile_cfg.instance);
                let (instance_url, instance_key) = normalize_instance_url(raw_instance)?;
                let read_only_lock_reason = if cli.read_only {
                    Some("`--read-only` / `SNCFR_READ_ONLY` is active".to_string())
                } else if profile_cfg.read_only {
                    Some(format!(
                        "profile '{profile_name}' has `read_only = true` in config.toml"
                    ))
                } else {
                    None
                };

                return Ok(ResolvedProfile {
                    name: profile_name.to_string(),
                    instance_url,
                    instance_key,
                    auth_method: profile_cfg.auth_method,
                    username: profile_cfg.username.clone(),
                    read_only_lock_reason,
                    views: profile_cfg.views.clone(),
                });
            } else if cli.profile.is_some() && cli.instance.is_none() {
                let available: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
                let remediation = if available.is_empty() {
                    "No profiles are configured in `~/.config/sncfr/config.toml`. Run `sncfr auth login --instance <instance>`.".to_string()
                } else {
                    format!("Configured profiles: {}", available.join(", "))
                };
                return Err(SncfrError::InvalidArgs {
                    message: format!("Profile '{profile_name}' not found in config.toml"),
                    remediation: Some(remediation),
                });
            }
        }

        // Fallback: new or ad-hoc profile when `--instance` / `SNCFR_INSTANCE` is supplied directly
        if let Some(raw_instance) = cli.instance.as_deref() {
            let (instance_url, instance_key) = normalize_instance_url(raw_instance)?;
            let read_only_lock_reason = if cli.read_only {
                Some("`--read-only` / `SNCFR_READ_ONLY` is active".to_string())
            } else {
                None
            };
            return Ok(ResolvedProfile {
                name: cli.profile.clone().unwrap_or_else(|| "adhoc".to_string()),
                instance_url,
                instance_key,
                auth_method: AuthMethod::Sso,
                username: None,
                read_only_lock_reason,
                views: BTreeMap::new(),
            });
        }

        Err(SncfrError::InvalidArgs {
            message: "No ServiceNow profile or instance configured".to_string(),
            remediation: Some(
                "Pass `--instance https://<name>.service-now.com` or configure a profile in `~/.config/sncfr/config.toml`."
                    .to_string(),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    #[test]
    fn normalizes_instance_urls_and_rejects_non_https_remote() {
        let (url, key) = normalize_instance_url("example").expect("shorthand");
        assert_eq!(url.as_str(), "https://example.service-now.com/");
        assert_eq!(key, "example.service-now.com");

        let (url2, key2) =
            normalize_instance_url("https://example.service-now.com/now/nav/ui").expect("full url");
        assert_eq!(url2.as_str(), "https://example.service-now.com/");
        assert_eq!(key2, "example.service-now.com");

        // Loopback HTTP allowed for wiremock tests
        let (mock_url, mock_key) =
            normalize_instance_url("http://127.0.0.1:45678").expect("loopback http");
        assert_eq!(mock_url.as_str(), "http://127.0.0.1:45678/");
        assert_eq!(mock_key, "127.0.0.1_45678");

        // Remote HTTP rejected
        let err = normalize_instance_url("http://example.service-now.com").unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
    }

    #[test]
    fn parses_spec_config_toml_and_resolves_profile_and_views() {
        let toml_str = r#"
default_profile = "prod"

[profiles.prod]
instance = "https://mycompany.service-now.com"
auth_method = "sso"
read_only = true

[profiles.prod.views]
my-active = { table = "task", query = "assigned_toDYNAMIC90d1921e5f510100a9ad2572f2b477fe^active=true" }
team-triage = { table = "incident", query = "assignment_group.name=Cloud Platform^active=true^priorityIN1,2" }
"#;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, toml_str).expect("write config");

        let cfg = AppConfig::load_from_path(&path).expect("load config");
        let cli = Cli::try_parse_from(["sncfr", "list", "@team-triage"]).expect("parse cli");
        let resolved = cfg.resolve_profile(&cli).expect("resolve profile");

        assert_eq!(resolved.name, "prod");
        assert_eq!(resolved.instance_key, "mycompany.service-now.com");
        assert_eq!(resolved.auth_method, AuthMethod::Sso);
        assert!(resolved.is_read_only_locked());

        let view = resolved
            .resolve_saved_view("@team-triage")
            .expect("resolve saved view");
        assert_eq!(view.table, "incident");
        assert_eq!(
            view.query,
            "assignment_group.name=Cloud Platform^active=true^priorityIN1,2"
        );

        let missing_view_err = resolved.resolve_saved_view("@nonexistent").unwrap_err();
        assert_eq!(missing_view_err.code().exit_code(), 2);
        assert!(
            missing_view_err
                .remediation()
                .unwrap_or_default()
                .contains("@my-active")
        );
    }

    #[test]
    fn roundtrips_config_save_and_adhoc_instance_override() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("config.toml");

        let mut cfg = AppConfig {
            default_profile: Some("dev".to_string()),
            profiles: BTreeMap::new(),
        };
        cfg.profiles.insert(
            "dev".to_string(),
            ProfileConfig {
                instance: "dev12345".to_string(),
                auth_method: AuthMethod::ApiKey,
                username: None,
                read_only: false,
                views: BTreeMap::new(),
            },
        );
        cfg.save_to_path(&path).expect("save config");

        let loaded = AppConfig::load_from_path(&path).expect("reload config");
        assert_eq!(loaded, cfg);

        // Ad-hoc instance when config is empty
        let empty = AppConfig::default();
        let cli = Cli::try_parse_from(["sncfr", "--instance", "mycompany", "doctor"])
            .expect("parse adhoc");
        let resolved = empty.resolve_profile(&cli).expect("resolve adhoc");
        assert_eq!(resolved.name, "adhoc");
        assert_eq!(resolved.instance_key, "mycompany.service-now.com");
        assert!(!resolved.is_read_only_locked());

        // Passing both `--profile <new_name>` and `--instance <url>` succeeds for initial `auth login`
        let new_profile_cli = Cli::try_parse_from([
            "sncfr",
            "auth",
            "login",
            "--instance",
            "https://example.service-now.com",
            "--profile",
            "prod",
        ])
        .expect("parse auth login with new profile");
        let new_resolved = empty
            .resolve_profile(&new_profile_cli)
            .expect("resolve new profile with explicit instance");
        assert_eq!(new_resolved.name, "prod");
        assert_eq!(new_resolved.instance_key, "example.service-now.com");
    }
}
