use crate::cache::{CachedGroup, CachedIdentity, InstanceCache};
use crate::cli::{AuthImportArgs, AuthLoginArgs, Cli};
use crate::client::{ClientAuth, ReadOnlyClient, extract_field_display, extract_field_value};
use crate::config::{
    AppConfig, AuthMethod, ResolvedProfile, default_config_path, normalize_instance_url,
};
use crate::error::SncfrError;
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use reqwest::header::{COOKIE, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

const KEYRING_SERVICE: &str = "sncfr";

/// Persisted credential bundle stored in the OS Keychain (or `SNCFR_CREDENTIALS_FILE` override).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub instance_url: String,
    pub updated_at: DateTime<Utc>,
    pub payload: CredentialPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CredentialPayload {
    SsoSession {
        cookie: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_token: Option<String>,
    },
    ApiKey {
        header_name: String,
        token: String,
    },
    Basic {
        username: String,
        password: String,
    },
    Bearer {
        token: String,
    },
}

impl CredentialPayload {
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::SsoSession { .. } => "sso-session",
            Self::ApiKey { .. } => "api-key",
            Self::Basic { .. } => "basic",
            Self::Bearer { .. } => "bearer",
        }
    }

    pub const fn auth_method(&self) -> AuthMethod {
        match self {
            Self::SsoSession { .. } => AuthMethod::Sso,
            Self::ApiKey { .. } => AuthMethod::ApiKey,
            Self::Basic { .. } => AuthMethod::Basic,
            Self::Bearer { .. } => AuthMethod::Oauth,
        }
    }
}

impl StoredCredentials {
    pub fn new(instance_url: impl Into<String>, payload: CredentialPayload) -> Self {
        Self {
            instance_url: instance_url.into(),
            updated_at: Utc::now(),
            payload,
        }
    }

    pub fn to_client_auth(&self) -> ClientAuth {
        match &self.payload {
            CredentialPayload::SsoSession { cookie, user_token } => ClientAuth::SsoSession {
                cookie: cookie.clone(),
                user_token: user_token.clone(),
            },
            CredentialPayload::ApiKey { header_name, token } => ClientAuth::ApiKey {
                header_name: header_name.clone(),
                token: token.clone(),
            },
            CredentialPayload::Basic { username, password } => ClientAuth::Basic {
                username: username.clone(),
                password: password.clone(),
            },
            CredentialPayload::Bearer { token } => ClientAuth::Bearer {
                token: token.clone(),
            },
        }
    }
}

/// Abstracts credential storage across the OS Keychain (`keyring`) and an optional file-backed store
/// (`SNCFR_CREDENTIALS_FILE`) for headless/test environments.
#[derive(Debug, Clone)]
pub enum CredentialStore {
    Keyring,
    File(PathBuf),
}

impl CredentialStore {
    /// Returns the active [`CredentialStore`]: uses `SNCFR_CREDENTIALS_FILE` if set, otherwise OS Keychain.
    pub fn default_store() -> Self {
        if let Ok(path) = std::env::var("SNCFR_CREDENTIALS_FILE")
            && !path.trim().is_empty()
        {
            Self::File(PathBuf::from(path))
        } else {
            Self::Keyring
        }
    }

    /// Loads [`StoredCredentials`] for `instance_key`.
    pub fn load(&self, instance_key: &str) -> Result<Option<StoredCredentials>, SncfrError> {
        match self {
            Self::Keyring => {
                let entry = keyring::Entry::new(KEYRING_SERVICE, instance_key).map_err(|e| {
                    SncfrError::NetworkOrInstance {
                        message: format!("Failed to access OS Keychain for '{instance_key}': {e}"),
                        status: None,
                        remediation: Some(
                            "Ensure your OS Keychain is unlocked or set `SNCFR_CREDENTIALS_FILE` in headless environments."
                                .to_string(),
                        ),
                    }
                })?;
                match entry.get_password() {
                    Ok(raw) => {
                        let creds: StoredCredentials =
                            serde_json::from_str(&raw).map_err(|e| SncfrError::InvalidArgs {
                                message: format!(
                                    "Corrupt credentials in OS Keychain for '{instance_key}': {e}"
                                ),
                                remediation: Some(
                                    "Run `sncfr auth login` or `sncfr auth import` to refresh credentials."
                                        .to_string(),
                                ),
                            })?;
                        Ok(Some(creds))
                    }
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(SncfrError::NetworkOrInstance {
                        message: format!(
                            "Failed to read credentials from OS Keychain for '{instance_key}': {e}"
                        ),
                        status: None,
                        remediation: None,
                    }),
                }
            }
            Self::File(path) => {
                let map = load_file_map(path)?;
                Ok(map.get(instance_key).cloned())
            }
        }
    }

    /// Saves [`StoredCredentials`] for `instance_key`.
    pub fn save(&self, instance_key: &str, creds: &StoredCredentials) -> Result<(), SncfrError> {
        match self {
            Self::Keyring => {
                let entry = keyring::Entry::new(KEYRING_SERVICE, instance_key).map_err(|e| {
                    SncfrError::NetworkOrInstance {
                        message: format!("Failed to open OS Keychain for '{instance_key}': {e}"),
                        status: None,
                        remediation: None,
                    }
                })?;
                let raw = serde_json::to_string(creds).map_err(|e| SncfrError::InvalidArgs {
                    message: format!("Failed to serialize credentials: {e}"),
                    remediation: None,
                })?;
                entry
                    .set_password(&raw)
                    .map_err(|e| SncfrError::NetworkOrInstance {
                        message: format!(
                            "Failed to store credentials in OS Keychain for '{instance_key}': {e}"
                        ),
                        status: None,
                        remediation: Some(
                            "Ensure your OS Keychain is unlocked or set `SNCFR_CREDENTIALS_FILE`."
                                .to_string(),
                        ),
                    })
            }
            Self::File(path) => {
                let mut map = load_file_map(path)?;
                map.insert(instance_key.to_string(), creds.clone());
                save_file_map(path, &map)
            }
        }
    }

    /// Deletes stored credentials for `instance_key`. Returns `Ok(true)` if an entry was removed.
    pub fn delete(&self, instance_key: &str) -> Result<bool, SncfrError> {
        match self {
            Self::Keyring => {
                let entry = keyring::Entry::new(KEYRING_SERVICE, instance_key).map_err(|e| {
                    SncfrError::NetworkOrInstance {
                        message: format!("Failed to open OS Keychain for '{instance_key}': {e}"),
                        status: None,
                        remediation: None,
                    }
                })?;
                match entry.delete_credential() {
                    Ok(()) => Ok(true),
                    Err(keyring::Error::NoEntry) => Ok(false),
                    Err(e) => Err(SncfrError::NetworkOrInstance {
                        message: format!(
                            "Failed to delete credentials from OS Keychain for '{instance_key}': {e}"
                        ),
                        status: None,
                        remediation: None,
                    }),
                }
            }
            Self::File(path) => {
                let mut map = load_file_map(path)?;
                let existed = map.remove(instance_key).is_some();
                save_file_map(path, &map)?;
                Ok(existed)
            }
        }
    }
}

fn load_file_map(path: &PathBuf) -> Result<BTreeMap<String, StoredCredentials>, SncfrError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Failed to read credentials file '{}': {e}", path.display()),
        remediation: None,
    })?;
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&raw).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Invalid JSON in credentials file '{}': {e}", path.display()),
        remediation: None,
    })
}

fn save_file_map(
    path: &PathBuf,
    map: &BTreeMap<String, StoredCredentials>,
) -> Result<(), SncfrError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to create directory for credentials file '{}': {e}",
                parent.display()
            ),
            remediation: None,
        })?;
    }
    let raw = serde_json::to_string_pretty(map).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Failed to serialize credentials file: {e}"),
        remediation: None,
    })?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &raw).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Failed to write credentials temp file: {e}"),
        remediation: None,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Failed to finalize credentials file: {e}"),
        remediation: None,
    })?;
    Ok(())
}

/// Resolves [`ClientAuth`] for `profile` by checking environment variables first, then [`CredentialStore`].
pub fn resolve_client_auth(
    profile: &ResolvedProfile,
    store: &CredentialStore,
) -> Result<ClientAuth, SncfrError> {
    // 1. Check explicit environment variable overrides (`docs/SPEC.md` Section 3.1)
    if let Ok(cookie) = std::env::var("SNCFR_COOKIE")
        && !cookie.trim().is_empty()
    {
        let user_token = std::env::var("SNCFR_USER_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        return Ok(ClientAuth::SsoSession {
            cookie: cookie.trim().to_string(),
            user_token,
        });
    }

    if let Ok(api_key) = std::env::var("SNCFR_API_KEY")
        && !api_key.trim().is_empty()
    {
        let header_name = std::env::var("SNCFR_API_KEY_HEADER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "x-sn-apikey".to_string());
        return Ok(ClientAuth::ApiKey {
            header_name,
            token: api_key.trim().to_string(),
        });
    }

    if let Ok(bearer) = std::env::var("SNCFR_BEARER_TOKEN")
        && !bearer.trim().is_empty()
    {
        return Ok(ClientAuth::Bearer {
            token: bearer.trim().to_string(),
        });
    }

    if let (Ok(user), Ok(pass)) = (
        std::env::var("SNCFR_USERNAME"),
        std::env::var("SNCFR_PASSWORD"),
    ) && !user.trim().is_empty()
    {
        return Ok(ClientAuth::Basic {
            username: user.trim().to_string(),
            password: pass,
        });
    }

    // 2. Load from CredentialStore (OS Keychain or file store)
    if let Some(stored) = store.load(&profile.instance_key)? {
        return Ok(stored.to_client_auth());
    }

    Err(SncfrError::AuthRequired {
        profile: profile.name.clone(),
    })
}

/// Parsed result from `sncfr auth import` (either from flags, a DevTools "Copy as cURL" snippet, or raw headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedAuth {
    /// Discovered instance URL if a full URL was present in a pasted `curl` command.
    pub discovered_instance: Option<Url>,
    /// Extracted credential payload.
    pub payload: CredentialPayload,
}

/// Parses credentials from [`AuthImportArgs`] (explicit flags, `--file`, or `stdin`).
pub fn parse_auth_import_args(args: &AuthImportArgs) -> Result<ImportedAuth, SncfrError> {
    if let Some(cookie) = &args.cookie
        && !cookie.trim().is_empty()
    {
        return Ok(ImportedAuth {
            discovered_instance: None,
            payload: CredentialPayload::SsoSession {
                cookie: cookie.trim().to_string(),
                user_token: args
                    .user_token
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            },
        });
    }

    let raw_input = if let Some(path) = &args.file {
        fs::read_to_string(path).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Failed to read import file '{}': {e}", path.display()),
            remediation: None,
        })?
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| SncfrError::InvalidArgs {
                message: format!("Failed to read credentials from stdin: {e}"),
                remediation: None,
            })?;
        buf
    };

    parse_imported_credentials(&raw_input)
}

/// Parses a pasted browser DevTools "Copy as cURL" command or raw HTTP headers into [`ImportedAuth`].
pub fn parse_imported_credentials(raw: &str) -> Result<ImportedAuth, SncfrError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "No credential input provided to `sncfr auth import`".to_string(),
            remediation: Some(
                "Paste a browser DevTools 'Copy as cURL' command via stdin, pass `--file`, or specify `--cookie` and `--user-token`."
                    .to_string(),
            ),
        });
    }

    // Join backslash-continued lines from multiline cURL commands
    let normalized = trimmed.replace("\\\r\n", " ").replace("\\\n", " ");
    let tokens = tokenize_shell_words(&normalized);

    let mut discovered_instance: Option<Url> = None;
    let mut cookies: Vec<String> = Vec::new();
    let mut user_token: Option<String> = None;
    let mut api_key: Option<(String, String)> = None;
    let mut bearer: Option<String> = None;
    let mut basic: Option<(String, String)> = None;

    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        match tok.as_str() {
            "-H" | "--header" if i + 1 < tokens.len() => {
                parse_header_line(
                    &tokens[i + 1],
                    &mut cookies,
                    &mut user_token,
                    &mut api_key,
                    &mut bearer,
                );
                i += 2;
                continue;
            }
            "-b" | "--cookie" if i + 1 < tokens.len() => {
                let c = tokens[i + 1].trim();
                if !c.is_empty() {
                    cookies.push(c.to_string());
                }
                i += 2;
                continue;
            }
            "-u" | "--user" if i + 1 < tokens.len() => {
                if let Some((u, p)) = tokens[i + 1].split_once(':') {
                    basic = Some((u.to_string(), p.to_string()));
                }
                i += 2;
                continue;
            }
            _ => {
                if (tok.starts_with("https://") || tok.starts_with("http://"))
                    && discovered_instance.is_none()
                    && let Ok(mut u) = Url::parse(tok)
                {
                    u.set_path("");
                    u.set_query(None);
                    u.set_fragment(None);
                    discovered_instance = Some(u);
                }
            }
        }
        i += 1;
    }

    // Also parse line-by-line in case raw HTTP headers (`Cookie: ...`, `X-UserToken: ...`) were pasted directly
    if cookies.is_empty() && api_key.is_none() && bearer.is_none() && basic.is_none() {
        for line in trimmed.lines() {
            parse_header_line(
                line.trim(),
                &mut cookies,
                &mut user_token,
                &mut api_key,
                &mut bearer,
            );
        }
    }

    if !cookies.is_empty() {
        let combined_cookie = cookies.join("; ");
        return Ok(ImportedAuth {
            discovered_instance,
            payload: CredentialPayload::SsoSession {
                cookie: combined_cookie,
                user_token,
            },
        });
    }

    if let Some((header_name, token)) = api_key {
        return Ok(ImportedAuth {
            discovered_instance,
            payload: CredentialPayload::ApiKey { header_name, token },
        });
    }

    if let Some(token) = bearer {
        return Ok(ImportedAuth {
            discovered_instance,
            payload: CredentialPayload::Bearer { token },
        });
    }

    if let Some((username, password)) = basic {
        return Ok(ImportedAuth {
            discovered_instance,
            payload: CredentialPayload::Basic { username, password },
        });
    }

    Err(SncfrError::InvalidArgs {
        message: "Could not find a `Cookie`, `X-UserToken`, `x-sn-apikey`, or `Authorization` header in the imported input".to_string(),
        remediation: Some(
            "In browser DevTools -> Network tab, right-click any `/api/now/...` request -> Copy -> Copy as cURL, then pipe it into `sncfr auth import`."
                .to_string(),
        ),
    })
}

fn parse_header_line(
    line: &str,
    cookies: &mut Vec<String>,
    user_token: &mut Option<String>,
    api_key: &mut Option<(String, String)>,
    bearer: &mut Option<String>,
) {
    let Some((raw_name, raw_val)) = line.split_once(':') else {
        return;
    };
    let name = raw_name.trim().to_lowercase();
    let val = raw_val.trim();
    if val.is_empty() {
        return;
    }

    match name.as_str() {
        "cookie" => cookies.push(val.to_string()),
        "x-usertoken" => *user_token = Some(val.to_string()),
        "x-sn-apikey" => *api_key = Some(("x-sn-apikey".to_string(), val.to_string())),
        "authorization" => {
            if let Some(tok) = val
                .strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
            {
                *bearer = Some(tok.trim().to_string());
            }
        }
        _ => {}
    }
}

fn tokenize_shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
        } else if in_double {
            if c == '"' {
                in_double = false;
            } else if c == '\\' {
                if let Some(next_c) = chars.next() {
                    current.push(next_c);
                }
            } else {
                current.push(c);
            }
        } else {
            match c {
                '\'' => {
                    // Handle ANSI-C quoting $'...'
                    if current.ends_with('$') {
                        current.pop();
                    }
                    in_single = true;
                }
                '"' => in_double = true,
                '\\' => {
                    if let Some(next_c) = chars.next()
                        && !next_c.is_whitespace()
                    {
                        current.push(next_c);
                    }
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(c),
            }
        }
    }

    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Extracts `g_ck` (`X-UserToken`) from ServiceNow HTML or inline script blocks.
pub fn extract_g_ck_from_html(html: &str) -> Option<String> {
    for pattern in [
        "window.g_ck = '",
        "window.g_ck = \"",
        "window.g_ck='",
        "window.g_ck=\"",
        "var g_ck = '",
        "var g_ck = \"",
        "\"g_ck\":\"",
        "'g_ck':'",
    ] {
        if let Some(idx) = html.find(pattern) {
            let rest = &html[idx + pattern.len()..];
            let end_quote = if pattern.ends_with('\'') { '\'' } else { '"' };
            if let Some(end_idx) = rest.find(end_quote) {
                let candidate = rest[..end_idx].trim();
                if candidate.len() >= 16 {
                    return Some(candidate.to_string());
                }
            }
        }
    }
    None
}

/// Attempts to fetch a fresh `g_ck` (`X-UserToken`) from the ServiceNow instance using an existing session `Cookie`.
pub async fn fetch_g_ck_with_cookie(
    base_url: &Url,
    cookie: &str,
) -> Result<Option<String>, SncfrError> {
    let cookie_header = HeaderValue::from_str(cookie).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Invalid Cookie header value: {e}"),
        remediation: None,
    })?;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to build HTTP client: {e}"),
            status: None,
            remediation: None,
        })?;

    for path in ["/now/nav/ui/home", "/navpage.do", "/$sp.do"] {
        if let Ok(url) = base_url.join(path)
            && let Ok(resp) = http
                .get(url)
                .header(COOKIE, cookie_header.clone())
                .header(USER_AGENT, concat!("sncfr/", env!("CARGO_PKG_VERSION")))
                .send()
                .await
            && resp.status().is_success()
            && let Ok(html) = resp.text().await
            && let Some(token) = extract_g_ck_from_html(&html)
        {
            return Ok(Some(token));
        }
    }

    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthImportSummary {
    pub profile: String,
    pub instance_url: String,
    pub instance_key: String,
    pub credential_kind: String,
    pub has_user_token: bool,
    pub auto_fetched_user_token: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthLogoutSummary {
    pub profile: String,
    pub instance_url: String,
    pub instance_key: String,
    pub removed: bool,
}

/// Executes `sncfr auth import`, resolving the instance from CLI/config or the imported cURL command,
/// optionally fetching `g_ck` if only a session `Cookie` was supplied, and persisting to [`CredentialStore`].
pub async fn execute_auth_import(
    cli: &Cli,
    config: &mut AppConfig,
    args: &AuthImportArgs,
    store: &CredentialStore,
) -> Result<AuthImportSummary, SncfrError> {
    let mut imported = parse_auth_import_args(args)?;

    let (profile_name, instance_url, instance_key) = match config.resolve_profile(cli) {
        Ok(resolved) => {
            let name = if resolved.name == "adhoc" {
                cli.profile.as_deref().unwrap_or("default").to_string()
            } else {
                resolved.name
            };
            (name, resolved.instance_url, resolved.instance_key)
        }
        Err(err) => {
            if let Some(discovered) = &imported.discovered_instance {
                let (url, key) = normalize_instance_url(discovered.as_str())?;
                let name = cli.profile.as_deref().unwrap_or("default").to_string();
                (name, url, key)
            } else {
                return Err(err);
            }
        }
    };

    let mut auto_fetched_user_token = false;
    if let CredentialPayload::SsoSession {
        ref cookie,
        ref mut user_token,
    } = imported.payload
        && user_token.is_none()
        && let Ok(Some(fetched)) = fetch_g_ck_with_cookie(&instance_url, cookie).await
    {
        *user_token = Some(fetched);
        auto_fetched_user_token = true;
    }

    let has_user_token = matches!(
        &imported.payload,
        CredentialPayload::SsoSession {
            user_token: Some(_),
            ..
        }
    );
    let credential_kind = imported.payload.kind_str().to_string();
    let auth_method = imported.payload.auth_method();

    let creds = StoredCredentials::new(
        instance_url.as_str().trim_end_matches('/'),
        imported.payload,
    );
    store.save(&instance_key, &creds)?;

    // Ensure profile exists in config.toml so subsequent invocations work without `--instance`
    config.upsert_profile(&profile_name, &instance_url, auth_method);
    if let Ok(cfg_path) = default_config_path() {
        let _ = config.save_to_path(&cfg_path);
    }

    Ok(AuthImportSummary {
        profile: profile_name,
        instance_url: instance_url.as_str().trim_end_matches('/').to_string(),
        instance_key,
        credential_kind,
        has_user_token,
        auto_fetched_user_token,
    })
}

/// Executes `sncfr auth logout`, removing stored credentials from [`CredentialStore`].
pub fn execute_auth_logout(
    profile: &ResolvedProfile,
    store: &CredentialStore,
) -> Result<AuthLogoutSummary, SncfrError> {
    let removed = store.delete(&profile.instance_key)?;
    Ok(AuthLogoutSummary {
        profile: profile.name.clone(),
        instance_url: profile
            .instance_url
            .as_str()
            .trim_end_matches('/')
            .to_string(),
        instance_key: profile.instance_key.clone(),
        removed,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthLoginSummary {
    pub profile: String,
    pub instance_url: String,
    pub instance_key: String,
    pub browser_executable: String,
    pub profile_dir: String,
    pub has_user_token: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct CdpTarget {
    #[serde(rename = "type", default)]
    target_type: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CdpCookie {
    name: String,
    value: String,
    #[serde(default)]
    domain: String,
}

/// Discovers the user's managed Chromium-based browser executable (Chrome, Edge, Brave, Arc, Chromium).
pub fn discover_managed_browser(explicit: Option<&Path>) -> Result<PathBuf, SncfrError> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(SncfrError::InvalidArgs {
            message: format!("Specified browser executable '{}' does not exist", path.display()),
            remediation: Some(
                "Pass a valid path to `--browser` or use `sncfr auth import` in headless environments."
                    .to_string(),
            ),
        });
    }

    if let Ok(env_browser) = std::env::var("SNCFR_BROWSER")
        && !env_browser.trim().is_empty()
    {
        let p = PathBuf::from(env_browser.trim());
        if p.exists() {
            return Ok(p);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        candidates.extend([
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            PathBuf::from("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
            PathBuf::from("/Applications/Arc.app/Contents/MacOS/Arc"),
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        ]);
    }

    #[cfg(target_os = "linux")]
    {
        for bin in [
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "microsoft-edge-stable",
            "brave-browser",
            "chromium",
            "chromium-browser",
        ] {
            for prefix in ["/usr/bin", "/usr/local/bin", "/snap/bin"] {
                candidates.push(PathBuf::from(prefix).join(bin));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "LocalAppData"] {
            if let Ok(base) = std::env::var(env_key) {
                candidates.push(PathBuf::from(&base).join(r"Google\Chrome\Application\chrome.exe"));
                candidates
                    .push(PathBuf::from(&base).join(r"Microsoft\Edge\Application\msedge.exe"));
                candidates.push(
                    PathBuf::from(&base).join(r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                );
            }
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(SncfrError::InvalidArgs {
        message: "Could not locate a managed Chromium browser (Chrome, Edge, Brave, Arc) on this system"
            .to_string(),
        remediation: Some(
            "Pass `--browser /path/to/chrome` or use `sncfr auth import` to import a session from any browser."
                .to_string(),
        ),
    })
}

/// Returns the isolated browser profile directory (`~/.local/share/sncfr/browser-profile/<instance_key>`).
pub fn browser_profile_dir(instance_key: &str) -> Result<PathBuf, SncfrError> {
    if let Ok(custom) = std::env::var("SNCFR_BROWSER_PROFILE_DIR")
        && !custom.trim().is_empty()
    {
        return Ok(PathBuf::from(custom).join(instance_key));
    }

    let base_dirs = directories::BaseDirs::new().ok_or_else(|| SncfrError::InvalidArgs {
        message: "Unable to determine user home directory for isolated browser profile".to_string(),
        remediation: Some("Set `SNCFR_BROWSER_PROFILE_DIR` explicitly.".to_string()),
    })?;

    Ok(base_dirs
        .home_dir()
        .join(".local")
        .join("share")
        .join("sncfr")
        .join("browser-profile")
        .join(instance_key))
}

fn pick_ephemeral_port() -> Result<u16, SncfrError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| SncfrError::NetworkOrInstance {
        message: format!("Failed to bind local loopback port for CDP: {e}"),
        status: None,
        remediation: None,
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to inspect local loopback port: {e}"),
            status: None,
            remediation: None,
        })?
        .port();
    Ok(port)
}

/// Polls a local CDP HTTP/WebSocket endpoint until a valid ServiceNow session (`Cookie` + `window.g_ck`)
/// is active on `instance_url`, then closes the browser via `Browser.close` and returns `(cookie, user_token)`.
pub async fn capture_session_via_cdp(
    cdp_port: u16,
    instance_url: &Url,
    timeout: Duration,
) -> Result<(String, Option<String>), SncfrError> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to construct CDP HTTP client: {e}"),
            status: None,
            remediation: None,
        })?;

    let list_url = format!("http://127.0.0.1:{cdp_port}/json/list");
    let target_host = instance_url.host_str().unwrap_or_default().to_lowercase();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if let Ok(resp) = http.get(&list_url).send().await
            && resp.status().is_success()
            && let Ok(targets) = resp.json::<Vec<CdpTarget>>().await
        {
            for target in targets {
                if target.target_type != "page" {
                    continue;
                }
                let Some(ws_url) = target.web_socket_debugger_url.as_deref() else {
                    continue;
                };
                // Only inspect pages once navigation has landed on (or returned to) the ServiceNow instance host
                let is_on_instance = Url::parse(&target.url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_lowercase))
                    .is_some_and(|h| h == target_host);
                if !is_on_instance {
                    continue;
                }

                if let Ok(Some((cookie, g_ck))) =
                    probe_cdp_page_session(ws_url, instance_url, &target_host).await
                {
                    return Ok((cookie, Some(g_ck)));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    Err(SncfrError::AuthExpired {
        instance: target_host,
    })
}

async fn probe_cdp_page_session(
    ws_url: &str,
    instance_url: &Url,
    target_host: &str,
) -> Result<Option<(String, String)>, SncfrError> {
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to connect to CDP WebSocket '{ws_url}': {e}"),
            status: None,
            remediation: None,
        })?;

    // 1. Evaluate `window.g_ck`
    let eval_cmd = json!({
        "id": 1,
        "method": "Runtime.evaluate",
        "params": {
            "expression": "typeof window.g_ck === 'string' && window.g_ck.length >= 16 ? window.g_ck : null",
            "returnByValue": true
        }
    });
    let _ = ws.send(Message::Text(eval_cmd.to_string().into())).await;
    let eval_resp = read_cdp_response_by_id(&mut ws, 1).await?;
    let mut g_ck = eval_resp
        .pointer("/result/result/value")
        .and_then(Value::as_str)
        .map(str::to_string);

    // 2. Fetch all domain cookies via `Network.getCookies`
    let cookies_cmd = json!({
        "id": 2,
        "method": "Network.getCookies",
        "params": {
            "urls": [instance_url.as_str()]
        }
    });
    let _ = ws.send(Message::Text(cookies_cmd.to_string().into())).await;
    let cookies_resp = read_cdp_response_by_id(&mut ws, 2).await?;

    let cookies_val = cookies_resp
        .pointer("/result/cookies")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let cdp_cookies: Vec<CdpCookie> = serde_json::from_value(cookies_val).unwrap_or_default();

    let mut pairs = Vec::new();
    let mut has_sn_session_cookie = false;
    for c in cdp_cookies {
        let domain_clean = c.domain.trim_start_matches('.').to_lowercase();
        if !domain_clean.is_empty() && !target_host.ends_with(&domain_clean) {
            continue;
        }
        if matches!(
            c.name.as_str(),
            "JSESSIONID" | "glide_user_route" | "glide_session_store" | "glide_user_activity"
        ) && !c.value.is_empty()
        {
            has_sn_session_cookie = true;
        }
        pairs.push(format!("{}={}", c.name, c.value));
    }

    if !has_sn_session_cookie || pairs.is_empty() {
        let _ = ws.close(None).await;
        return Ok(None);
    }

    let cookie_header = pairs.join("; ");

    // If `window.g_ck` wasn't directly on the top frame, try fetching it via the session cookie
    if g_ck.is_none()
        && let Ok(Some(fetched)) = fetch_g_ck_with_cookie(instance_url, &cookie_header).await
    {
        g_ck = Some(fetched);
    }

    let Some(token) = g_ck else {
        let _ = ws.close(None).await;
        return Ok(None);
    };

    // 3. Close the isolated `--app` browser window cleanly
    let close_cmd = json!({
        "id": 3,
        "method": "Browser.close",
        "params": {}
    });
    let _ = ws.send(Message::Text(close_cmd.to_string().into())).await;
    let _ = ws.close(None).await;

    Ok(Some((cookie_header, token)))
}

async fn read_cdp_response_by_id<S>(ws: &mut S, expected_id: u64) -> Result<Value, SncfrError>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                return Err(SncfrError::NetworkOrInstance {
                    message: format!("Timed out waiting for CDP response id={expected_id}"),
                    status: None,
                    remediation: None,
                });
            }
            maybe_msg = ws.next() => {
                let Some(Ok(msg)) = maybe_msg else {
                    return Err(SncfrError::NetworkOrInstance {
                        message: "CDP WebSocket closed unexpectedly".to_string(),
                        status: None,
                        remediation: None,
                    });
                };
                if let Message::Text(text) = msg
                    && let Ok(val) = serde_json::from_str::<Value>(&text)
                    && val.get("id").and_then(Value::as_u64) == Some(expected_id)
                {
                    return Ok(val);
                }
            }
        }
    }
}

/// Executes `sncfr auth login`: launches the user's managed Chromium browser in an isolated `--app` window
/// with CDP enabled, waits for Corporate SSO completion, extracts cookies + `window.g_ck`, closes the window,
/// and saves the credentials to [`CredentialStore`].
pub async fn execute_auth_login(
    cli: &Cli,
    config: &mut AppConfig,
    args: &AuthLoginArgs,
    store: &CredentialStore,
) -> Result<AuthLoginSummary, SncfrError> {
    if cli.no_interactive {
        return Err(SncfrError::AuthRequired {
            profile: cli
                .profile
                .clone()
                .or_else(|| config.default_profile.clone())
                .unwrap_or_else(|| "default".to_string()),
        });
    }

    let resolved = config.resolve_profile(cli)?;
    let profile_name = if resolved.name == "adhoc" {
        cli.profile.as_deref().unwrap_or("default").to_string()
    } else {
        resolved.name.clone()
    };

    let browser_exe = discover_managed_browser(args.browser.as_deref())?;
    let profile_dir = browser_profile_dir(&resolved.instance_key)?;
    fs::create_dir_all(&profile_dir).map_err(|e| SncfrError::InvalidArgs {
        message: format!(
            "Failed to create isolated browser profile directory '{}': {e}",
            profile_dir.display()
        ),
        remediation: None,
    })?;

    let cdp_port = pick_ephemeral_port()?;
    let app_arg = format!("--app={}", resolved.instance_url.as_str());
    let user_data_arg = format!("--user-data-dir={}", profile_dir.display());
    let debug_port_arg = format!("--remote-debugging-port={cdp_port}");
    let allow_origins_arg = format!("--remote-allow-origins=http://127.0.0.1:{cdp_port}");

    let mut child = Command::new(&browser_exe)
        .arg(&app_arg)
        .arg(&user_data_arg)
        .arg(&debug_port_arg)
        .arg(&allow_origins_arg)
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!(
                "Failed to launch managed browser '{}': {e}",
                browser_exe.display()
            ),
            status: None,
            remediation: Some(
                "Pass `--browser /path/to/chrome` or use `sncfr auth import`.".to_string(),
            ),
        })?;

    let capture_res = capture_session_via_cdp(
        cdp_port,
        &resolved.instance_url,
        Duration::from_secs(args.timeout_secs),
    )
    .await;

    // Ensure the child browser process is cleaned up if still alive
    let _ = child.kill();
    let _ = child.wait();

    let (cookie, user_token) = capture_res?;
    let has_user_token = user_token.is_some();

    let creds = StoredCredentials::new(
        resolved.instance_url.as_str().trim_end_matches('/'),
        CredentialPayload::SsoSession { cookie, user_token },
    );
    store.save(&resolved.instance_key, &creds)?;

    config.upsert_profile(&profile_name, &resolved.instance_url, AuthMethod::Sso);
    if let Ok(cfg_path) = default_config_path() {
        let _ = config.save_to_path(&cfg_path);
    }

    Ok(AuthLoginSummary {
        profile: profile_name,
        instance_url: resolved
            .instance_url
            .as_str()
            .trim_end_matches('/')
            .to_string(),
        instance_key: resolved.instance_key,
        browser_executable: browser_exe.display().to_string(),
        profile_dir: profile_dir.display().to_string(),
        has_user_token,
    })
}

/// Returns `true` if the current invocation is allowed to auto-launch the isolated Corporate SSO
/// browser window upon encountering `AuthRequired` or `AuthExpired` (`docs/SPEC.md` Section 3.2).
pub const fn can_auto_reauth(
    cli: &Cli,
    profile: &ResolvedProfile,
    is_stdin_tty: bool,
    is_stdout_tty: bool,
) -> bool {
    is_stdin_tty
        && is_stdout_tty
        && !cli.no_interactive
        && matches!(profile.auth_method, AuthMethod::Sso)
}

/// Resolves an authenticated [`ReadOnlyClient`] for `profile`, automatically launching [`execute_auth_login`]
/// if credentials are missing and `can_auto_reauth` is true.
pub async fn resolve_authenticated_client(
    cli: &Cli,
    config: &mut AppConfig,
    profile: &ResolvedProfile,
    store: &CredentialStore,
    is_stdin_tty: bool,
    is_stdout_tty: bool,
) -> Result<ReadOnlyClient, SncfrError> {
    let auth = match resolve_client_auth(profile, store) {
        Ok(auth) => auth,
        Err(SncfrError::AuthRequired { .. })
            if can_auto_reauth(cli, profile, is_stdin_tty, is_stdout_tty) =>
        {
            eprintln!(
                "No active ServiceNow session for '{}'; launching isolated SSO browser window...",
                profile.instance_url
            );
            let default_login = AuthLoginArgs {
                browser: None,
                timeout_secs: 180,
            };
            execute_auth_login(cli, config, &default_login, store).await?;
            resolve_client_auth(profile, store)?
        }
        Err(err) => return Err(err),
    };

    ReadOnlyClient::new(profile.instance_url.clone(), auth)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusSummary {
    pub authenticated: bool,
    pub profile: String,
    pub instance_url: String,
    pub auth_method: String,
    pub read_only_locked: bool,
    pub identity: CachedIdentity,
}

/// Resolves the current `@me` [`CachedIdentity`] (`sys_user` + `sys_user_grmember` active groups),
/// reading from `cache` when `force_refresh == false` and writing the updated identity to `identity.json`.
pub async fn resolve_current_identity(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    force_refresh: bool,
) -> Result<CachedIdentity, SncfrError> {
    if !force_refresh && let Ok(Some(cached)) = cache.read_identity() {
        return Ok(cached);
    }

    // 1. Try querying `sys_user` for `javascript:gs.getUserID()`
    let sys_user_query = [
        ("sysparm_query", "sys_id=javascript:gs.getUserID()"),
        ("sysparm_limit", "1"),
        ("sysparm_display_value", "all"),
        ("sysparm_fields", "sys_id,user_name,name,email"),
    ];

    let mut resolved_user: Option<(String, String, String, Option<String>)> = None;
    match client
        .get_json::<Value>("/api/now/table/sys_user", &sys_user_query)
        .await
    {
        Ok(resp) => {
            if let Some(first) = resp
                .get("result")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                && let Some(sys_id) = extract_field_value(first, "sys_id")
            {
                let user_name =
                    extract_field_value(first, "user_name").unwrap_or_else(|| sys_id.clone());
                let display_name =
                    extract_field_display(first, "name").unwrap_or_else(|| user_name.clone());
                let email = extract_field_value(first, "email");
                resolved_user = Some((sys_id, user_name, display_name, email));
            }
        }
        Err(SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. }) => {
            return Err(SncfrError::AuthExpired {
                instance: client.base_url().as_str().trim_end_matches('/').to_string(),
            });
        }
        Err(_) => {
            // Fall through to `/api/now/ui/user/current_user` if `sys_user` is ACL-restricted
        }
    }

    // 2. Fallback to `/api/now/ui/user/current_user` if `sys_user` was empty or 403 Forbidden
    if resolved_user.is_none() {
        let ui_resp: Value = client
            .get_json("/api/now/ui/user/current_user", &[])
            .await?;
        let res = ui_resp.get("result").unwrap_or(&ui_resp);
        let sys_id = res
            .get("user_sys_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SncfrError::AuthExpired {
                instance: client.base_url().as_str().trim_end_matches('/').to_string(),
            })?
            .to_string();
        let user_name = res
            .get("user_name")
            .and_then(Value::as_str)
            .unwrap_or(&sys_id)
            .to_string();
        let display_name = res
            .get("user_display_name")
            .and_then(Value::as_str)
            .unwrap_or(&user_name)
            .to_string();
        resolved_user = Some((sys_id, user_name, display_name, None));
    }

    let (sys_id, user_name, display_name, email) =
        resolved_user.ok_or_else(|| SncfrError::AuthExpired {
            instance: client.base_url().as_str().trim_end_matches('/').to_string(),
        })?;

    // 3. Query `sys_user_grmember` for the user's active assignment groups (degrade gracefully on 403)
    let gr_query_str = format!("user={sys_id}^group.active=true");
    let gr_query = [
        ("sysparm_query", gr_query_str.as_str()),
        ("sysparm_display_value", "all"),
        ("sysparm_fields", "group"),
        ("sysparm_limit", "200"),
    ];

    let mut groups = Vec::new();
    if let Ok(gr_resp) = client
        .get_json::<Value>("/api/now/table/sys_user_grmember", &gr_query)
        .await
        && let Some(rows) = gr_resp.get("result").and_then(Value::as_array)
    {
        for row in rows {
            if let Some(group_id) = extract_field_value(row, "group") {
                let group_name =
                    extract_field_display(row, "group").unwrap_or_else(|| group_id.clone());
                if !groups.iter().any(|g: &CachedGroup| g.sys_id == group_id) {
                    groups.push(CachedGroup {
                        sys_id: group_id,
                        name: group_name,
                    });
                }
            }
        }
    }

    let identity = CachedIdentity {
        sys_id,
        user_name,
        display_name,
        email,
        groups,
    };

    let _ = cache.write_identity(&identity);
    Ok(identity)
}

/// Executes `sncfr auth status`: verifies active session validity against the instance and returns [`AuthStatusSummary`].
pub async fn execute_auth_status(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
) -> Result<AuthStatusSummary, SncfrError> {
    let identity = resolve_current_identity(client, cache, true).await?;
    Ok(AuthStatusSummary {
        authenticated: true,
        profile: profile.name.clone(),
        instance_url: profile
            .instance_url
            .as_str()
            .trim_end_matches('/')
            .to_string(),
        auth_method: profile.auth_method.as_str().to_string(),
        read_only_locked: profile.is_read_only_locked(),
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_chrome_devtools_copy_as_curl_with_cookie_and_user_token() {
        let curl_cmd = r#"curl 'https://mycompany.service-now.com/api/now/ui/user/current_user' \
  -H 'Accept: application/json' \
  -H 'X-UserToken: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f' \
  -b 'JSESSIONID=node0123; glide_user_route=glide.abcd; glide_session_store=XYZ'"#;

        let imported = parse_imported_credentials(curl_cmd).expect("parse curl");
        assert_eq!(
            imported.discovered_instance.as_ref().map(|u| u.as_str()),
            Some("https://mycompany.service-now.com/")
        );
        match imported.payload {
            CredentialPayload::SsoSession { cookie, user_token } => {
                assert_eq!(
                    cookie,
                    "JSESSIONID=node0123; glide_user_route=glide.abcd; glide_session_store=XYZ"
                );
                assert_eq!(
                    user_token.as_deref(),
                    Some(
                        "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"
                    )
                );
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn parses_raw_headers_and_extracts_g_ck_from_html() {
        let raw_headers = "Cookie: JSESSIONID=111; glide_user_route=glide.222\nX-UserToken: gck_token_1234567890123456";
        let imported = parse_imported_credentials(raw_headers).expect("parse raw headers");
        assert_eq!(
            imported.payload,
            CredentialPayload::SsoSession {
                cookie: "JSESSIONID=111; glide_user_route=glide.222".to_string(),
                user_token: Some("gck_token_1234567890123456".to_string()),
            }
        );

        let html = r#"<html><head><script>var g_ck = '0123456789abcdef0123456789abcdef0123456789abcdef';</script></head></html>"#;
        assert_eq!(
            extract_g_ck_from_html(html).as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn file_credential_store_saves_loads_and_deletes_cleanly() {
        let dir = tempdir().expect("tempdir");
        let cred_file = dir.path().join("creds.json");
        let store = CredentialStore::File(cred_file);

        let creds = StoredCredentials::new(
            "https://acme.service-now.com",
            CredentialPayload::SsoSession {
                cookie: "JSESSIONID=abc".to_string(),
                user_token: Some("tok123".to_string()),
            },
        );
        store
            .save("acme.service-now.com", &creds)
            .expect("save creds");

        let loaded = store
            .load("acme.service-now.com")
            .expect("load creds")
            .expect("creds present");
        assert_eq!(loaded.payload, creds.payload);

        assert!(store.delete("acme.service-now.com").expect("delete creds"));
        assert!(
            store
                .load("acme.service-now.com")
                .expect("load after delete")
                .is_none()
        );
    }

    #[tokio::test]
    async fn fetches_g_ck_from_nav_ui_home_when_importing_cookie_only() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/now/nav/ui/home"))
            .and(header("cookie", "JSESSIONID=mock_session_123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<html><script>window.g_ck = 'fedcba9876543210fedcba9876543210';</script></html>",
            ))
            .mount(&server)
            .await;

        let base_url = Url::parse(&server.uri()).expect("mock url");
        let g_ck = fetch_g_ck_with_cookie(&base_url, "JSESSIONID=mock_session_123")
            .await
            .expect("fetch g_ck")
            .expect("g_ck found");
        assert_eq!(g_ck, "fedcba9876543210fedcba9876543210");
    }

    #[tokio::test]
    async fn captures_session_via_cdp_websocket_and_closes_browser() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as AsyncTcpListener;

        // 1. Bind a mock CDP WebSocket server
        let ws_listener = AsyncTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ws");
        let ws_port = ws_listener.local_addr().expect("ws addr").port();

        let ws_handle = tokio::spawn(async move {
            let (stream, _) = ws_listener.accept().await.expect("accept ws");
            let mut ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("ws handshake");

            let mut closed_browser = false;
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let req: Value = serde_json::from_str(&text).expect("parse cdp req");
                let id = req["id"].as_u64().unwrap_or(0);
                let method = req["method"].as_str().unwrap_or_default();
                match method {
                    "Runtime.evaluate" => {
                        let resp = json!({
                            "id": id,
                            "result": {
                                "result": {
                                    "type": "string",
                                    "value": "gck_from_cdp_0123456789abcdef0123456789"
                                }
                            }
                        });
                        ws.send(Message::Text(resp.to_string().into()))
                            .await
                            .expect("send eval resp");
                    }
                    "Network.getCookies" => {
                        let resp = json!({
                            "id": id,
                            "result": {
                                "cookies": [
                                    {
                                        "name": "JSESSIONID",
                                        "value": "cdp_node_999",
                                        "domain": ".mycompany.service-now.com"
                                    },
                                    {
                                        "name": "glide_user_route",
                                        "value": "glide.cdp_route",
                                        "domain": "mycompany.service-now.com"
                                    }
                                ]
                            }
                        });
                        ws.send(Message::Text(resp.to_string().into()))
                            .await
                            .expect("send cookies resp");
                    }
                    "Browser.close" => {
                        closed_browser = true;
                        break;
                    }
                    _ => {}
                }
            }
            closed_browser
        });

        // 2. Bind a mock CDP HTTP `/json/list` server
        let http_listener = AsyncTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind http");
        let cdp_port = http_listener.local_addr().expect("http addr").port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = http_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = serde_json::to_string(&json!([
                    {
                        "type": "page",
                        "url": "https://mycompany.service-now.com/now/nav/ui/home",
                        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{ws_port}/devtools/page/1")
                    }
                ]))
                .expect("json list");
                let http_resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(http_resp.as_bytes()).await;
            }
        });

        let instance_url =
            Url::parse("https://mycompany.service-now.com").expect("parse instance url");
        let (cookie, user_token) =
            capture_session_via_cdp(cdp_port, &instance_url, Duration::from_secs(5))
                .await
                .expect("capture cdp session");

        assert_eq!(
            cookie,
            "JSESSIONID=cdp_node_999; glide_user_route=glide.cdp_route"
        );
        assert_eq!(
            user_token.as_deref(),
            Some("gck_from_cdp_0123456789abcdef0123456789")
        );
        assert!(ws_handle.await.expect("ws task joined"));
    }

    #[test]
    fn context_aware_auto_reauth_respects_tty_and_no_interactive() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["sncfr", "list", "--instance", "acme"]).expect("cli");
        let profile = AppConfig::default().resolve_profile(&cli).expect("profile");

        assert!(can_auto_reauth(&cli, &profile, true, true));
        assert!(!can_auto_reauth(&cli, &profile, false, true));
        assert!(!can_auto_reauth(&cli, &profile, true, false));

        let non_interactive_cli =
            Cli::try_parse_from(["sncfr", "--no-interactive", "list", "--instance", "acme"])
                .expect("cli no-interactive");
        assert!(!can_auto_reauth(&non_interactive_cli, &profile, true, true));
    }
}
