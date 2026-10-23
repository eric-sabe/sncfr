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
                crate::debug_log!(
                    "auth",
                    "Loading credentials from OS Keychain (service='{KEYRING_SERVICE}', account='{instance_key}')"
                );
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
                        log_loaded_credentials("OS Keychain", instance_key, &creds);
                        Ok(Some(creds))
                    }
                    Err(keyring::Error::NoEntry) => {
                        crate::debug_log!(
                            "auth",
                            "No stored credentials found in OS Keychain for '{instance_key}'"
                        );
                        Ok(None)
                    }
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
                crate::debug_log!(
                    "auth",
                    "Loading credentials from file store '{}' for '{instance_key}'",
                    path.display()
                );
                let map = load_file_map(path)?;
                let found = map.get(instance_key).cloned();
                if let Some(creds) = &found {
                    log_loaded_credentials("file store", instance_key, creds);
                } else {
                    crate::debug_log!(
                        "auth",
                        "No stored credentials found in file store for '{instance_key}'"
                    );
                }
                Ok(found)
            }
        }
    }

    /// Saves [`StoredCredentials`] for `instance_key`.
    pub fn save(&self, instance_key: &str, creds: &StoredCredentials) -> Result<(), SncfrError> {
        match self {
            Self::Keyring => {
                crate::debug_log!(
                    "auth",
                    "Saving {} credentials to OS Keychain (service='{KEYRING_SERVICE}', account='{instance_key}')",
                    creds.payload.kind_str()
                );
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
                    })?;
                crate::debug_log!(
                    "auth",
                    "Successfully saved credentials to OS Keychain for '{instance_key}'"
                );
                Ok(())
            }
            Self::File(path) => {
                crate::debug_log!(
                    "auth",
                    "Saving {} credentials to file store '{}' for '{instance_key}'",
                    creds.payload.kind_str(),
                    path.display()
                );
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

fn log_loaded_credentials(source: &str, instance_key: &str, creds: &StoredCredentials) {
    match &creds.payload {
        CredentialPayload::SsoSession { cookie, user_token } => {
            crate::debug_log!(
                "auth",
                "Loaded sso-session from {source} for '{instance_key}' (updated_at={}, {}, X-UserToken={})",
                creds.updated_at.to_rfc3339(),
                crate::log::summarize_cookie_names(cookie),
                crate::log::redact_token(user_token.as_deref())
            );
        }
        other => {
            crate::debug_log!(
                "auth",
                "Loaded {} credentials from {source} for '{instance_key}' (updated_at={})",
                other.kind_str(),
                creds.updated_at.to_rfc3339()
            );
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
    if html.contains("NOW.user.name = 'guest'")
        || html.contains("NOW.user.name=\"guest\"")
        || html.contains("\"user_name\":\"guest\"")
        || html.contains("\"user_name\": \"guest\"")
        || html.contains("5136503cc611227c0183e96598c4f706")
    {
        return None;
    }
    for pattern in [
        "window.g_ck = '",
        "window.g_ck = \"",
        "window.g_ck='",
        "window.g_ck=\"",
        "var g_ck = '",
        "var g_ck = \"",
        "var g_ck='",
        "var g_ck=\"",
        "\"g_ck\":\"",
        "\"g_ck\": \"",
        "'g_ck':'",
        "'g_ck': '",
        "\"userToken\":\"",
        "\"userToken\": \"",
        "\"sessionToken\":\"",
        "\"sessionToken\": \"",
        "\"glide.security.csrf_token\":\"",
        "\"glide.security.csrf_token\": \"",
        "name=\"sysparm_ck\" value=\"",
        "name='sysparm_ck' value='",
        "id=\"sysparm_ck\" value=\"",
    ] {
        if let Some(idx) = html.find(pattern) {
            let rest = &html[idx + pattern.len()..];
            let end_quote = if pattern.ends_with('\'') { '\'' } else { '"' };
            if let Some(end_idx) = rest.find(end_quote) {
                let candidate = rest[..end_idx].trim();
                if candidate.len() >= 16
                    && candidate.len() <= 160
                    && !candidate.eq_ignore_ascii_case("true")
                    && !candidate.eq_ignore_ascii_case("false")
                {
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
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to build HTTP client: {e}"),
            status: None,
            remediation: None,
        })?;

    let target_host = base_url.host_str().unwrap_or_default();
    for path in [
        "/now/nav/ui/home",
        "/sys_user.do?sys_id=javascript:gs.getUserID()&sysparm_nostack=true",
        "/welcome.do",
        "/navpage.do",
        "/$sp.do",
    ] {
        if let Ok(url) = base_url.join(path)
            && let Ok(resp) = http
                .get(url)
                .header(COOKIE, cookie_header.clone())
                .header(USER_AGENT, concat!("sncfr/", env!("CARGO_PKG_VERSION")))
                .send()
                .await
            && resp.status().is_success()
            && resp
                .url()
                .host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(target_host))
            && !resp.url().path().contains("login.do")
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

/// Discovers the user's managed Chromium-based browser executable (preferring the OS default browser
/// among Edge, Chrome, Brave, Arc, and Chromium, or an explicit `--browser` path/shorthand).
pub fn discover_managed_browser(explicit: Option<&Path>) -> Result<PathBuf, SncfrError> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        if let Some(s) = path.to_str()
            && let Some(resolved) = resolve_browser_shorthand(s)
        {
            return Ok(resolved);
        }
        return Err(SncfrError::InvalidArgs {
            message: format!("Specified browser '{}' was not found", path.display()),
            remediation: Some(
                "Pass `--browser edge`, `--browser chrome`, `--browser brave`, a full executable path, or use `sncfr auth import`."
                    .to_string(),
            ),
        });
    }

    if let Ok(env_browser) = std::env::var("SNCFR_BROWSER")
        && !env_browser.trim().is_empty()
    {
        let trimmed = env_browser.trim();
        let p = PathBuf::from(trimmed);
        if p.exists() {
            return Ok(p);
        }
        if let Some(resolved) = resolve_browser_shorthand(trimmed) {
            return Ok(resolved);
        }
    }

    // 1. Prefer the user's OS default browser if it is a supported Chromium browser
    if let Some(default_kind) = detect_os_default_chromium_browser() {
        crate::debug_log!("browser", "OS default browser detected as '{default_kind}'");
        if let Some(resolved) = resolve_browser_shorthand(default_kind) {
            crate::debug_log!(
                "browser",
                "Selected OS default Chromium browser executable: {}",
                resolved.display()
            );
            return Ok(resolved);
        }
    }

    // 2. Fallback to installed Chromium browsers
    for shorthand in ["edge", "chrome", "brave", "arc", "chromium"] {
        if let Some(resolved) = resolve_browser_shorthand(shorthand) {
            crate::debug_log!(
                "browser",
                "Selected fallback Chromium browser executable ({shorthand}): {}",
                resolved.display()
            );
            return Ok(resolved);
        }
    }

    Err(SncfrError::InvalidArgs {
        message: "Could not locate a managed Chromium browser (Edge, Chrome, Brave, Arc) on this system"
            .to_string(),
        remediation: Some(
            "Pass `--browser /path/to/browser` or use `sncfr auth import` to import a session from any browser."
                .to_string(),
        ),
    })
}

fn resolve_browser_shorthand(name: &str) -> Option<PathBuf> {
    let lower = name.trim().to_ascii_lowercase();
    let kind = if lower.contains("edge") {
        "edge"
    } else if lower.contains("brave") {
        "brave"
    } else if lower.contains("arc") {
        "arc"
    } else if lower.contains("chromium") {
        "chromium"
    } else if lower.contains("chrome") {
        "chrome"
    } else {
        return None;
    };

    let mut candidates: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        match kind {
            "edge" => candidates.push(PathBuf::from(
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            )),
            "chrome" => candidates.push(PathBuf::from(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )),
            "brave" => candidates.push(PathBuf::from(
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            )),
            "arc" => candidates.push(PathBuf::from("/Applications/Arc.app/Contents/MacOS/Arc")),
            "chromium" => candidates.push(PathBuf::from(
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            )),
            _ => {}
        }
    }

    #[cfg(target_os = "linux")]
    {
        let bins: &[&str] = match kind {
            "edge" => &["microsoft-edge", "microsoft-edge-stable"],
            "chrome" => &["google-chrome", "google-chrome-stable"],
            "brave" => &["brave-browser"],
            "chromium" => &["chromium", "chromium-browser"],
            _ => &[],
        };
        for bin in bins {
            for prefix in ["/usr/bin", "/usr/local/bin", "/snap/bin"] {
                candidates.push(PathBuf::from(prefix).join(bin));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        for env_key in ["ProgramFiles", "ProgramFiles(x86)", "LocalAppData"] {
            if let Ok(base) = std::env::var(env_key) {
                match kind {
                    "edge" => candidates
                        .push(PathBuf::from(&base).join(r"Microsoft\Edge\Application\msedge.exe")),
                    "chrome" => candidates
                        .push(PathBuf::from(&base).join(r"Google\Chrome\Application\chrome.exe")),
                    "brave" => candidates.push(
                        PathBuf::from(&base)
                            .join(r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                    ),
                    _ => {}
                }
            }
        }
    }

    candidates.into_iter().find(|p| p.exists())
}

fn detect_os_default_chromium_browser() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if let Some(base_dirs) = directories::BaseDirs::new() {
            let plist = base_dirs
                .home_dir()
                .join("Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist");
            if plist.exists()
                && let Ok(out) = Command::new("/usr/bin/plutil")
                    .args(["-convert", "json", "-o", "-"])
                    .arg(&plist)
                    .output()
                && out.status.success()
                && let Ok(val) = serde_json::from_slice::<Value>(&out.stdout)
                && let Some(handlers) = val.get("LSHandlers").and_then(Value::as_array)
            {
                for h in handlers {
                    let scheme = h
                        .get("LSHandlerURLScheme")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if scheme.eq_ignore_ascii_case("https") {
                        let role = h
                            .get("LSHandlerRoleAll")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_ascii_lowercase();
                        if role.contains("edgemac") {
                            return Some("edge");
                        } else if role.contains("chrome") {
                            return Some("chrome");
                        } else if role.contains("brave") {
                            return Some("brave");
                        } else if role.contains("thebrowser") {
                            return Some("arc");
                        } else if role.contains("chromium") {
                            return Some("chromium");
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice",
                "/v",
                "ProgId",
            ])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if text.contains("msedge") {
                return Some("edge");
            } else if text.contains("chrome") {
                return Some("chrome");
            } else if text.contains("brave") {
                return Some("brave");
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("xdg-settings")
            .args(["get", "default-web-browser"])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if text.contains("edge") {
                return Some("edge");
            } else if text.contains("chrome") {
                return Some("chrome");
            } else if text.contains("brave") {
                return Some("brave");
            } else if text.contains("chromium") {
                return Some("chromium");
            }
        }
    }

    None
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

/// If a previous `sncfr auth login` run was interrupted (`Ctrl+C`), an orphaned browser process
/// may still hold `SingletonLock` on `profile_dir` with an older `--remote-debugging-port`.
/// This helper closes any existing CDP browser listening on `DevToolsActivePort` and cleans up stale locks.
async fn cleanup_stale_browser_profile(profile_dir: &Path) {
    let active_port_file = profile_dir.join("DevToolsActivePort");
    if let Ok(contents) = fs::read_to_string(&active_port_file) {
        let mut lines = contents.lines();
        if let (Some(port_str), Some(ws_path)) = (lines.next(), lines.next())
            && let Ok(old_port) = port_str.trim().parse::<u16>()
        {
            let ws_url = format!("ws://127.0.0.1:{old_port}{}", ws_path.trim());
            if let Ok(Ok((mut ws, _))) = tokio::time::timeout(
                Duration::from_secs(1),
                tokio_tungstenite::connect_async(&ws_url),
            )
            .await
            {
                let close_cmd = json!({
                    "id": 99,
                    "method": "Browser.close",
                    "params": {}
                });
                let _ = ws.send(Message::Text(close_cmd.to_string().into())).await;
                let _ = ws.close(None).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    for lock_name in [
        "SingletonLock",
        "SingletonSocket",
        "SingletonCookie",
        "DevToolsActivePort",
    ] {
        let _ = fs::remove_file(profile_dir.join(lock_name));
    }
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
    let mut last_logged_host = String::new();
    let mut last_logged_diag = String::new();
    crate::debug_log!(
        "cdp",
        "Starting CDP session polling on {list_url} for target_host='{target_host}' (timeout={}s)",
        timeout.as_secs()
    );

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
                let parsed_url = Url::parse(&target.url).ok();
                if let Some(u) = &parsed_url
                    && let Some(h) = u.host_str()
                    && !h.is_empty()
                    && h != last_logged_host
                {
                    last_logged_host = h.to_string();
                    crate::debug_log!("cdp", "Browser active page navigated to: {}", target.url);
                    if h.eq_ignore_ascii_case(&target_host) {
                        eprintln!(
                            "  [SSO] Browser is on ServiceNow ({h}{}) — checking session...",
                            u.path()
                        );
                    } else {
                        eprintln!(
                            "  [SSO] Browser is on Identity Provider ({h}) — please complete sign-in in the browser window..."
                        );
                    }
                }

                // Only inspect pages once navigation has landed on (or returned to) an authenticated ServiceNow page
                let is_on_instance = parsed_url.is_some_and(|u| {
                    let host_ok = u
                        .host_str()
                        .is_some_and(|h| h.eq_ignore_ascii_case(&target_host));
                    let path_lower = u.path().to_ascii_lowercase();
                    let is_login_or_redirect = path_lower.contains("login.do")
                        || path_lower.contains("saml_redirector.do")
                        || path_lower.contains("logout");
                    host_ok && !is_login_or_redirect
                });
                if !is_on_instance {
                    continue;
                }

                if let Ok(Some((cookie, g_ck))) = probe_cdp_page_session(
                    ws_url,
                    instance_url,
                    &target.url,
                    &target_host,
                    &mut last_logged_diag,
                )
                .await
                {
                    return Ok((cookie, g_ck));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    crate::debug_log!(
        "cdp",
        "Timed out waiting for valid ServiceNow session on '{target_host}' (last_diag='{last_logged_diag}')"
    );
    Err(SncfrError::AuthExpired {
        instance: target_host,
    })
}

const CDP_SESSION_PROBE_JS: &str = r#"
(async () => {
  const href = (window.location && window.location.href) || '';
  const p = ((window.location && window.location.pathname) || '').toLowerCase();
  if (
    !href ||
    href.startsWith('about:') ||
    p.includes('login') ||
    p.includes('saml_redirector') ||
    p.includes('logout') ||
    p.includes('auth_redirect') ||
    p.includes('external_logout') ||
    href.includes('SAMLRequest=') ||
    href.includes('SAMLResponse=') ||
    href.includes('RelayState=')
  ) {
    return '__DIAG__:login_or_redirect_url:' + p;
  }

  const isValidToken = (t) => {
    if (typeof t !== 'string') return false;
    const s = t.trim();
    return s.length >= 16 && s.length <= 160 && !/^(true|false|null|undefined)$/i.test(s);
  };

  // Install passive X-UserToken sniffer on fetch and XMLHttpRequest in this window
  const installSniffer = (w) => {
    try {
      if (!w || w.__sncfr_hooked) return;
      w.__sncfr_hooked = true;
      if (w.XMLHttpRequest && w.XMLHttpRequest.prototype) {
        const origSetHeader = w.XMLHttpRequest.prototype.setRequestHeader;
        w.XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
          try {
            if (typeof name === 'string' && name.toLowerCase() === 'x-usertoken' && isValidToken(value)) {
              window.__sncfr_captured_g_ck = value.trim();
            }
          } catch (_) {}
          return origSetHeader.apply(this, arguments);
        };
      }
      if (typeof w.fetch === 'function') {
        const origFetch = w.fetch;
        w.fetch = function(input, init) {
          try {
            const h = (init && init.headers) || (input && input.headers);
            if (h) {
              if (typeof h.get === 'function') {
                const v = h.get('X-UserToken') || h.get('x-usertoken');
                if (isValidToken(v)) window.__sncfr_captured_g_ck = v.trim();
              } else if (typeof h === 'object') {
                for (const k of Object.keys(h)) {
                  if (k.toLowerCase() === 'x-usertoken' && isValidToken(h[k])) {
                    window.__sncfr_captured_g_ck = h[k].trim();
                  }
                }
              }
            }
          } catch (_) {}
          return origFetch.apply(this, arguments);
        };
      }
    } catch (_) {}
  };

  const collectWindows = () => {
    const wins = [window];
    try {
      if (window.frames) {
        for (let i = 0; i < window.frames.length; i++) {
          if (window.frames[i] && !wins.includes(window.frames[i])) {
            wins.push(window.frames[i]);
          }
        }
      }
      const visitRoot = (root, depth) => {
        if (!root || depth > 5) return;
        const els = root.querySelectorAll ? root.querySelectorAll('*') : [];
        for (let i = 0; i < els.length; i++) {
          const el = els[i];
          if (el.tagName === 'IFRAME' && el.contentWindow && !wins.includes(el.contentWindow)) {
            wins.push(el.contentWindow);
          }
          if (el.shadowRoot) {
            visitRoot(el.shadowRoot, depth + 1);
          }
        }
      };
      visitRoot(document, 0);
    } catch (_) {}
    for (const w of wins) installSniffer(w);
    return wins;
  };

  const wins = collectWindows();

  const GUEST_SYS_ID = '5136503cc611227c0183e96598c4f706';
  const isRealUser = (name, sysId) => {
    if (sysId && sysId === GUEST_SYS_ID) return false;
    if (!name || typeof name !== 'string') return false;
    const norm = name.trim().toLowerCase();
    return norm.length > 0 && norm !== 'guest' && norm !== 'anonymous' && norm !== 'system';
  };

  const findUserInWin = (w) => {
    try {
      if (w.NOW && w.NOW.user && isRealUser(w.NOW.user.name || w.NOW.user.userName, w.NOW.user.userID)) {
        return w.NOW.user.name || w.NOW.user.userName;
      }
      if (w.NOW && isRealUser(w.NOW.user_name, w.NOW.user_id)) {
        return w.NOW.user_name;
      }
      if (w.ux_globals && w.ux_globals.sysprops && isRealUser(w.ux_globals.sysprops['user.name'], null)) {
        return w.ux_globals.sysprops['user.name'];
      }
    } catch (_) {}
    return null;
  };

  const findTokenInWin = (w) => {
    try {
      if (isValidToken(w.__sncfr_captured_g_ck)) return w.__sncfr_captured_g_ck.trim();
      if (isValidToken(w.g_ck)) return w.g_ck.trim();
      if (w.NOW) {
        if (isValidToken(w.NOW.g_ck)) return w.NOW.g_ck.trim();
        if (isValidToken(w.NOW.session_token)) return w.NOW.session_token.trim();
        if (isValidToken(w.NOW.user_token)) return w.NOW.user_token.trim();
      }
      if (w.ux_globals) {
        if (isValidToken(w.ux_globals.g_ck)) return w.ux_globals.g_ck.trim();
        if (isValidToken(w.ux_globals.sessionToken)) return w.ux_globals.sessionToken.trim();
        if (w.ux_globals.sysprops && isValidToken(w.ux_globals.sysprops['glide.security.csrf_token'])) {
          return w.ux_globals.sysprops['glide.security.csrf_token'].trim();
        }
      }
      if (w.document && w.document.querySelector) {
        const inp = w.document.querySelector('input[name="sysparm_ck"], #sysparm_ck');
        if (inp && isValidToken(inp.value)) return inp.value.trim();
        const meta = w.document.querySelector('meta[name="g_ck"]');
        if (meta && isValidToken(meta.content)) return meta.content.trim();
      }
    } catch (_) {}
    return null;
  };

  const extractFromText = (txt) => {
    if (!txt || typeof txt !== 'string') return null;
    if (
      txt.includes("NOW.user.name = 'guest'") ||
      txt.includes('NOW.user.name="guest"') ||
      txt.includes('"user_name":"guest"') ||
      txt.includes('"user_name": "guest"') ||
      txt.includes(GUEST_SYS_ID)
    ) {
      return null;
    }
    const regexes = [
      /(?:window\.g_ck|var\s+g_ck)\s*=\s*['"]([0-9a-zA-Z._-]{16,160})['"]/,
      /['"](?:g_ck|userToken|sessionToken|csrfToken|glide\.security\.csrf_token)['"]\s*:\s*['"]([0-9a-zA-Z._-]{16,160})['"]/,
      /name=['"]sysparm_ck['"][^>]*value=['"]([0-9a-zA-Z._-]{16,160})['"]/,
      /value=['"]([0-9a-zA-Z._-]{16,160})['"][^>]*name=['"]sysparm_ck['"]/,
      /id=['"]sysparm_ck['"][^>]*value=['"]([0-9a-zA-Z._-]{16,160})['"]/
    ];
    for (const re of regexes) {
      const m = txt.match(re);
      if (m && isValidToken(m[1])) {
        return m[1].trim();
      }
    }
    return null;
  };

  let authedUser = null;
  let token = null;
  for (const w of wins) {
    if (!authedUser) authedUser = findUserInWin(w);
    if (!token) token = findTokenInWin(w);
  }
  if (!token && document && document.documentElement) {
    token = extractFromText(document.documentElement.innerHTML);
  }

  const fetchTokenFromPages = async () => {
    if (typeof fetch !== 'function') return null;
    const urls = [
      '/sys_user.do?sys_id=javascript:gs.getUserID()&sysparm_nostack=true',
      '/welcome.do',
      '/stats.do',
      '/navpage.do',
      '/now/nav/ui/home',
      '/$sp.do'
    ];
    for (const url of urls) {
      try {
        const r = await fetch(url, { credentials: 'include' });
        if (r.ok && !(r.url || '').toLowerCase().includes('login')) {
          const hdrTok = r.headers && (r.headers.get('X-UserToken') || r.headers.get('x-usertoken'));
          if (isValidToken(hdrTok)) return hdrTok.trim();
          const txt = await r.text();
          const extracted = extractFromText(txt);
          if (isValidToken(extracted)) return extracted;
        }
      } catch (_) {}
    }
    return null;
  };

  if (!token && authedUser) {
    token = await fetchTokenFromPages();
  }

  // Always verify session authenticity against `/api/now/ui/user/current_user` when `fetch` is available
  let currentUserDiag = 'not_checked';
  if (typeof fetch === 'function') {
    try {
      const headers = { 'Accept': 'application/json' };
      if (isValidToken(token)) headers['X-UserToken'] = token;
      const r = await fetch('/api/now/ui/user/current_user', { credentials: 'include', headers });
      currentUserDiag = 'http_' + r.status;
      if (r.status === 401 || r.status === 403 || (r.url || '').toLowerCase().includes('login')) {
        return '__DIAG__:current_user_unauthenticated:status=' + r.status + ',path=' + p;
      }
      if (r.ok) {
        const hdrTok = r.headers && (r.headers.get('X-UserToken') || r.headers.get('x-usertoken'));
        if (!token && isValidToken(hdrTok)) token = hdrTok.trim();
        const data = await r.json();
        const res = (data && data.result) || data || {};
        const uName = res.user_name || res.userName || res.name || '';
        const uSysId = res.user_sys_id || res.sys_id || res.userID || '';
        if (!isRealUser(uName, uSysId)) {
          return '__DIAG__:guest_session:user=' + (uName || 'empty') + ',sys_id=' + (uSysId || 'empty') + ',path=' + p;
        }
        authedUser = uName;
        if (!token) {
          const bodyTok = res.user_token || res.g_ck || res.session_token;
          if (isValidToken(bodyTok)) token = bodyTok.trim();
        }
      }
    } catch (e) {
      currentUserDiag = 'err_' + (e && e.message ? e.message : 'fetch');
    }
  }

  if (!authedUser) {
    return '__DIAG__:no_authed_user:path=' + p + ',frames=' + wins.length + ',current_user=' + currentUserDiag;
  }

  if (!token) {
    token = await fetchTokenFromPages();
  }

  if (!isValidToken(token)) {
    return '__DIAG__:missing_g_ck:user=' + authedUser + ',path=' + p + ',frames=' + wins.length;
  }

  return token.trim();
})()
"#;

async fn probe_cdp_page_session(
    ws_url: &str,
    instance_url: &Url,
    page_url: &str,
    target_host: &str,
    last_logged_diag: &mut String,
) -> Result<Option<(String, Option<String>)>, SncfrError> {
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to connect to CDP WebSocket '{ws_url}': {e}"),
            status: None,
            remediation: None,
        })?;

    // 1. Evaluate `CDP_SESSION_PROBE_JS` inside the active ServiceNow tab
    let eval_cmd = json!({
        "id": 1,
        "method": "Runtime.evaluate",
        "params": {
            "expression": CDP_SESSION_PROBE_JS,
            "awaitPromise": true,
            "returnByValue": true
        }
    });
    let _ = ws.send(Message::Text(eval_cmd.to_string().into())).await;
    let eval_resp = read_cdp_response_by_id(&mut ws, 1).await?;
    let raw_eval = eval_resp
        .pointer("/result/result/value")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");

    if let Some(diag) = raw_eval.strip_prefix("__DIAG__:") {
        if *last_logged_diag != diag {
            *last_logged_diag = diag.to_string();
            crate::debug_log!("cdp", "ServiceNow page probe not ready yet: {diag}");
        }
        let _ = ws.close(None).await;
        return Ok(None);
    }

    let eval_str = if raw_eval.len() >= 16 {
        Some(raw_eval.to_string())
    } else {
        if *last_logged_diag != "empty_eval" {
            *last_logged_diag = "empty_eval".to_string();
            crate::debug_log!(
                "cdp",
                "ServiceNow page probe returned empty/short value on '{page_url}'"
            );
        }
        None
    };

    // Do NOT proceed or close the browser unless `CDP_SESSION_PROBE_JS` confirmed an authenticated
    // non-guest ServiceNow session and extracted a valid `g_ck` (`X-UserToken`).
    let Some(g_ck) = eval_str else {
        let _ = ws.close(None).await;
        return Ok(None);
    };

    crate::debug_log!(
        "cdp",
        "ServiceNow page probe succeeded on '{page_url}': X-UserToken={}",
        crate::log::redact_token(Some(&g_ck))
    );

    // 2. Fetch all domain cookies via `Network.getCookies`
    let cookies_cmd = json!({
        "id": 2,
        "method": "Network.getCookies",
        "params": {
            "urls": [instance_url.as_str(), page_url]
        }
    });
    let _ = ws.send(Message::Text(cookies_cmd.to_string().into())).await;
    let cookies_resp = read_cdp_response_by_id(&mut ws, 2).await?;

    let cookies_val = cookies_resp
        .pointer("/result/cookies")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let cdp_cookies: Vec<CdpCookie> = serde_json::from_value(cookies_val).unwrap_or_default();

    let mut cookie_map: BTreeMap<String, String> = BTreeMap::new();
    let mut has_sn_session_cookie = false;
    for c in cdp_cookies {
        if c.value.is_empty() {
            continue;
        }
        let domain_clean = c.domain.trim_start_matches('.').to_lowercase();
        if !domain_clean.is_empty() && !target_host.ends_with(&domain_clean) {
            continue;
        }
        if matches!(
            c.name.as_str(),
            "JSESSIONID" | "glide_user_route" | "glide_session_store" | "glide_user_activity"
        ) {
            has_sn_session_cookie = true;
        }
        cookie_map.insert(c.name, c.value);
    }

    if !has_sn_session_cookie || cookie_map.is_empty() {
        crate::debug_log!(
            "cdp",
            "No ServiceNow session cookie (JSESSIONID / glide_user_route / glide_session_store) found yet among {} cookies",
            cookie_map.len()
        );
        let _ = ws.close(None).await;
        return Ok(None);
    }

    let cookie_header = cookie_map
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");

    crate::debug_log!(
        "cdp",
        "Captured ServiceNow session cookies: {}",
        crate::log::summarize_cookie_names(&cookie_header)
    );

    // 3. Close the isolated `--app` browser window cleanly
    let close_cmd = json!({
        "id": 3,
        "method": "Browser.close",
        "params": {}
    });
    let _ = ws.send(Message::Text(close_cmd.to_string().into())).await;
    let _ = ws.close(None).await;
    crate::debug_log!("cdp", "Sent Browser.close to isolated SSO browser window");

    Ok(Some((cookie_header, Some(g_ck))))
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

    cleanup_stale_browser_profile(&profile_dir).await;

    let cdp_port = pick_ephemeral_port()?;
    let app_arg = format!("--app={}", resolved.instance_url.as_str());
    let user_data_arg = format!("--user-data-dir={}", profile_dir.display());
    let debug_port_arg = format!("--remote-debugging-port={cdp_port}");

    crate::debug_log!(
        "auth",
        "Spawning isolated browser: exe='{}' args=['{}', '{}', '{}', '--remote-allow-origins=*', '--no-first-run', '--no-default-browser-check']",
        browser_exe.display(),
        app_arg,
        user_data_arg,
        debug_port_arg
    );

    eprintln!(
        "Launching isolated SSO browser window for '{}' (profile '{}')...",
        resolved.instance_url, profile_name
    );
    eprintln!("  Browser: {}", browser_exe.display());
    eprintln!(
        "  Waiting up to {}s for ServiceNow SSO login to complete...",
        args.timeout_secs
    );

    let mut child = Command::new(&browser_exe)
        .arg(&app_arg)
        .arg(&user_data_arg)
        .arg(&debug_port_arg)
        .arg("--remote-allow-origins=*")
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

    if let Ok(cache) = InstanceCache::for_instance(&resolved.instance_key) {
        let _ = fs::remove_file(cache.dir().join("identity.json"));
    }

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
    const GUEST_SYS_ID: &str = "5136503cc611227c0183e96598c4f706";

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
    let mut table_auth_err = false;
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
                if sys_id != GUEST_SYS_ID && !user_name.eq_ignore_ascii_case("guest") {
                    let display_name =
                        extract_field_display(first, "name").unwrap_or_else(|| user_name.clone());
                    let email = extract_field_value(first, "email");
                    resolved_user = Some((sys_id, user_name, display_name, email));
                }
            }
        }
        Err(SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. }) => {
            table_auth_err = true;
        }
        Err(_) => {
            // Fall through to `/api/now/ui/user/current_user` if `sys_user` is ACL-restricted
        }
    }

    // 2. Fallback to `/api/now/ui/user/current_user` if `sys_user` was empty, 403 Forbidden, or restricted
    if resolved_user.is_none() {
        let ui_resp: Value = match client.get_json("/api/now/ui/user/current_user", &[]).await {
            Ok(v) => v,
            Err(_) if table_auth_err => {
                return Err(SncfrError::AuthExpired {
                    instance: client.base_url().as_str().trim_end_matches('/').to_string(),
                });
            }
            Err(e) => return Err(e),
        };
        let res = ui_resp.get("result").unwrap_or(&ui_resp);
        let sys_id = res
            .get("user_sys_id")
            .or_else(|| res.get("sys_id"))
            .or_else(|| res.get("userID"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != GUEST_SYS_ID)
            .ok_or_else(|| SncfrError::AuthExpired {
                instance: client.base_url().as_str().trim_end_matches('/').to_string(),
            })?
            .to_string();
        let user_name = res
            .get("user_name")
            .or_else(|| res.get("userName"))
            .or_else(|| res.get("name"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("guest"))
            .unwrap_or(&sys_id)
            .to_string();
        let display_name = res
            .get("user_display_name")
            .or_else(|| res.get("display_name"))
            .or_else(|| res.get("displayName"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
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
