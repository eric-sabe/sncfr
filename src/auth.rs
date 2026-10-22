use crate::cli::{AuthImportArgs, Cli};
use crate::client::ClientAuth;
use crate::config::{
    AppConfig, AuthMethod, ResolvedProfile, default_config_path, normalize_instance_url,
};
use crate::error::SncfrError;
use chrono::{DateTime, Utc};
use reqwest::header::{COOKIE, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
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
}
