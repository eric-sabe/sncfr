use crate::cli::Cli;
use crate::config::ResolvedProfile;
use crate::error::SncfrError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::header::{ACCEPT, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName, HeaderValue, LOCATION};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use url::Url;

/// Capability token required at compile time to construct a [`MutatingClient`].
///
/// Per `docs/SPEC.md` Section 4.1 and `docs/adr/0002-read-only-default-validated-dry-run.md`,
/// `WritePermit` has a private field and can only be issued by [`WritePermit::issue`].
#[derive(Debug)]
pub struct WritePermit {
    _private: (),
}

impl WritePermit {
    /// Evaluates whether the invocation is authorized to perform mutations against ServiceNow:
    /// - If `--write` was **not** passed on the CLI: returns `Ok(None)` (caller runs in Read-Only or Validated Dry-Run mode).
    /// - If `--write` **was** passed while `--read-only` (`SNCFR_READ_ONLY`) or profile `read_only = true` is set:
    ///   returns `Err(SncfrError::ReadOnlyLocked)` (exit code 6).
    /// - Otherwise: returns `Ok(Some(WritePermit))`.
    pub fn issue(cli: &Cli, profile: Option<&ResolvedProfile>) -> Result<Option<Self>, SncfrError> {
        if !cli.command.requests_write() {
            return Ok(None);
        }

        if cli.read_only {
            return Err(SncfrError::ReadOnlyLocked {
                reason: "`--read-only` / `SNCFR_READ_ONLY` is active while `--write` was requested"
                    .to_string(),
            });
        }

        if let Some(prof) = profile
            && let Some(reason) = &prof.read_only_lock_reason
        {
            return Err(SncfrError::ReadOnlyLocked {
                reason: reason.clone(),
            });
        }

        Ok(Some(Self { _private: () }))
    }
}

/// Authentication material attached to outbound ServiceNow REST requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuth {
    /// Corporate SSO browser session (`Cookie` header + `X-UserToken: <g_ck>`).
    SsoSession {
        cookie: String,
        user_token: Option<String>,
    },
    /// ServiceNow Inbound REST API Key (default header `x-sn-apikey`).
    ApiKey { header_name: String, token: String },
    /// HTTP Basic Authentication.
    Basic { username: String, password: String },
    /// OAuth 2.0 Bearer Token.
    Bearer { token: String },
}

impl ClientAuth {
    fn debug_summary(&self) -> String {
        match self {
            Self::SsoSession { cookie, user_token } => format!(
                "sso-session ({}, X-UserToken={})",
                crate::log::summarize_cookie_names(cookie),
                crate::log::redact_token(user_token.as_deref())
            ),
            Self::ApiKey { header_name, token } => format!(
                "api-key (header={header_name}, token={})",
                crate::log::redact_token(Some(token))
            ),
            Self::Basic { username, .. } => format!("basic (username={username})"),
            Self::Bearer { token } => {
                format!("bearer (token={})", crate::log::redact_token(Some(token)))
            }
        }
    }

    fn apply(&self, req: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, SncfrError> {
        match self {
            Self::SsoSession { cookie, user_token } => {
                let cookie_val =
                    HeaderValue::from_str(cookie).map_err(|e| SncfrError::InvalidArgs {
                        message: format!("Invalid characters in session Cookie header: {e}"),
                        remediation: Some(
                            "Re-run `sncfr auth login` or `sncfr auth import`.".to_string(),
                        ),
                    })?;
                let mut builder = req.header(COOKIE, cookie_val);
                if let Some(token) = user_token
                    && !token.trim().is_empty()
                {
                    let token_val = HeaderValue::from_str(token.trim()).map_err(|e| {
                        SncfrError::InvalidArgs {
                            message: format!("Invalid characters in X-UserToken header: {e}"),
                            remediation: Some(
                                "Re-run `sncfr auth login` or `sncfr auth import`.".to_string(),
                            ),
                        }
                    })?;
                    builder = builder.header("X-UserToken", token_val);
                }
                Ok(builder)
            }
            Self::ApiKey { header_name, token } => {
                let name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
                    SncfrError::InvalidArgs {
                        message: format!("Invalid API key header name '{header_name}': {e}"),
                        remediation: None,
                    }
                })?;
                let val = HeaderValue::from_str(token).map_err(|e| SncfrError::InvalidArgs {
                    message: format!("Invalid characters in API key token: {e}"),
                    remediation: None,
                })?;
                Ok(req.header(name, val))
            }
            Self::Basic { username, password } => Ok(req.basic_auth(username, Some(password))),
            Self::Bearer { token } => Ok(req.bearer_auth(token)),
        }
    }
}

/// Read-only ServiceNow HTTP client (`docs/SPEC.md` Section 4.1).
///
/// Capable only of `GET`, `HEAD`, and verified `GET`-only `/api/now/batch` requests.
#[derive(Debug, Clone)]
pub struct ReadOnlyClient {
    base_url: Url,
    http: reqwest::Client,
    auth: ClientAuth,
}

/// A single read-only (`GET`) sub-request inside a `/api/now/batch` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchGetSubRequest {
    /// Unique correlation ID within the batch (e.g., `"ticket"`, `"journal"`, `"attachments"`).
    pub id: String,
    /// Relative path and query string on the instance (e.g., `"/api/now/table/incident?sysparm_limit=1"`).
    pub url: String,
}

impl BatchGetSubRequest {
    pub fn new(id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct WireBatchEnvelope<'a> {
    batch_request_id: &'a str,
    rest_requests: Vec<WireBatchGetItem<'a>>,
}

#[derive(Debug, Serialize)]
struct WireBatchGetItem<'a> {
    id: &'a str,
    method: &'static str,
    url: String,
    exclude_response_headers: bool,
    headers: [WireBatchHeader; 1],
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct WireBatchHeader {
    pub name: String,
    pub value: String,
}

/// Decoded response from `/api/now/batch`.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    pub batch_request_id: Option<String>,
    #[serde(default)]
    pub serviced_requests: Vec<ServicedSubResponse>,
    #[serde(default)]
    pub unserviced_requests: Vec<serde_json::Value>,
}

impl BatchResponse {
    /// Looks up a serviced sub-response by its request `id`.
    pub fn get(&self, id: &str) -> Option<&ServicedSubResponse> {
        self.serviced_requests.iter().find(|r| r.id == id)
    }
}

/// Individual sub-response returned inside `serviced_requests` from `/api/now/batch`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServicedSubResponse {
    pub id: String,
    pub status_code: u16,
    #[serde(default)]
    pub status_text: Option<String>,
    /// Base64-encoded response payload.
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub execution_time: Option<u64>,
}

impl ServicedSubResponse {
    /// Returns `true` if this sub-request was denied by ServiceNow ACLs (`403 Forbidden`).
    pub const fn is_forbidden(&self) -> bool {
        self.status_code == 403
    }

    /// Returns `true` if this sub-request succeeded (`2xx`).
    pub const fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    /// Base64-decodes and deserializes the JSON body of this sub-response.
    pub fn decode_json<T: DeserializeOwned>(&self) -> Result<T, SncfrError> {
        if self.status_code == 401 {
            return Err(SncfrError::AuthExpired {
                instance: self.id.clone(),
            });
        }
        if self.status_code == 403 {
            return Err(SncfrError::AclForbidden {
                resource: self.id.clone(),
                details: self
                    .error_message
                    .clone()
                    .or_else(|| self.status_text.clone())
                    .unwrap_or_else(|| "Sub-request returned 403 Forbidden".to_string()),
            });
        }
        if self.status_code == 404 {
            return Err(SncfrError::NotFound {
                identifier: self.id.clone(),
                table: None,
            });
        }
        if !self.is_success() {
            return Err(SncfrError::NetworkOrInstance {
                message: format!(
                    "Batch sub-request '{}' failed with HTTP {}: {}",
                    self.id,
                    self.status_code,
                    self.error_message
                        .as_deref()
                        .or(self.status_text.as_deref())
                        .unwrap_or("unknown error")
                ),
                status: Some(self.status_code),
                remediation: None,
            });
        }

        let encoded = self.body.as_deref().unwrap_or("");
        // ServiceNow's Batch API may wrap base64 across lines; filter out ASCII whitespace first.
        let cleaned: String = encoded
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let bytes =
            BASE64_STANDARD
                .decode(&cleaned)
                .map_err(|e| SncfrError::NetworkOrInstance {
                    message: format!(
                        "Failed to decode base64 body for batch sub-request '{}': {e}",
                        self.id
                    ),
                    status: Some(self.status_code),
                    remediation: None,
                })?;

        serde_json::from_slice(&bytes).map_err(|e| SncfrError::NetworkOrInstance {
            message: format!(
                "Failed to parse JSON body for batch sub-request '{}': {e}",
                self.id
            ),
            status: Some(self.status_code),
            remediation: None,
        })
    }
}

impl ReadOnlyClient {
    /// Creates a new [`ReadOnlyClient`] configured with OS native root certificates (`rustls-tls-native-roots`).
    pub fn new(base_url: Url, auth: ClientAuth) -> Result<Self, SncfrError> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .user_agent(concat!("sncfr/", env!("CARGO_PKG_VERSION")))
            .default_headers(default_headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SncfrError::NetworkOrInstance {
                message: format!("Failed to initialize HTTP/TLS client: {e}"),
                status: None,
                remediation: None,
            })?;

        Ok(Self {
            base_url,
            http,
            auth,
        })
    }

    /// Returns the base instance [`Url`].
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Promotes this [`ReadOnlyClient`] into a [`MutatingClient`] using a verified [`WritePermit`].
    pub fn into_mutating(self, permit: WritePermit) -> MutatingClient {
        MutatingClient::new(self, permit)
    }

    /// Performs an authenticated `GET` request and deserializes the JSON response.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, SncfrError> {
        let url = self.endpoint_url(path)?;
        crate::debug_log!(
            "http",
            "GET {url} query={query:?} auth=[{}]",
            self.auth.debug_summary()
        );
        let started = Instant::now();
        let req = self.auth.apply(self.http.get(url).query(query))?;
        let resp = req.send().await.map_err(|e| self.map_reqwest_error(e))?;
        crate::debug_log!(
            "http",
            "GET {path} -> HTTP {} ({}ms)",
            resp.status(),
            started.elapsed().as_millis()
        );
        self.decode_json_response(resp, path).await
    }

    /// Performs an authenticated `GET` request and returns the raw response bytes (e.g., for attachment downloads).
    pub async fn get_bytes(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<u8>, SncfrError> {
        let url = self.endpoint_url(path)?;
        crate::debug_log!(
            "http",
            "GET (bytes) {url} query={query:?} auth=[{}]",
            self.auth.debug_summary()
        );
        let started = Instant::now();
        let req = self
            .auth
            .apply(self.http.get(url).header(ACCEPT, "*/*").query(query))?;
        let resp = req.send().await.map_err(|e| self.map_reqwest_error(e))?;
        let status = resp.status();
        crate::debug_log!(
            "http",
            "GET (bytes) {path} -> HTTP {status} ({}ms)",
            started.elapsed().as_millis()
        );
        if !status.is_success() {
            return Err(self.map_error_status(resp, path).await);
        }
        let bytes = resp.bytes().await.map_err(|e| self.map_reqwest_error(e))?;
        Ok(bytes.to_vec())
    }

    /// Performs an authenticated `HEAD` request and returns the HTTP status code.
    pub async fn head(&self, path: &str, query: &[(&str, &str)]) -> Result<u16, SncfrError> {
        let url = self.endpoint_url(path)?;
        crate::debug_log!(
            "http",
            "HEAD {url} query={query:?} auth=[{}]",
            self.auth.debug_summary()
        );
        let started = Instant::now();
        let req = self.auth.apply(self.http.head(url).query(query))?;
        let resp = req.send().await.map_err(|e| self.map_reqwest_error(e))?;
        let status = resp.status();
        crate::debug_log!(
            "http",
            "HEAD {path} -> HTTP {status} ({}ms)",
            started.elapsed().as_millis()
        );
        if status.as_u16() == 401 || status.is_redirection() {
            return Err(SncfrError::AuthExpired {
                instance: self.base_url.as_str().trim_end_matches('/').to_string(),
            });
        }
        Ok(status.as_u16())
    }

    /// Executes multiple read-only (`GET`) REST requests in a single round-trip via `/api/now/batch`.
    ///
    /// At the type level, [`BatchGetSubRequest`] only permits `GET` sub-requests.
    pub async fn batch_get(
        &self,
        batch_request_id: &str,
        requests: &[BatchGetSubRequest],
    ) -> Result<BatchResponse, SncfrError> {
        let url = self.endpoint_url("/api/now/batch")?;
        let sub_ids: Vec<&str> = requests.iter().map(|r| r.id.as_str()).collect();
        crate::debug_log!(
            "http",
            "POST {url} batch_id='{batch_request_id}' sub_requests={sub_ids:?} auth=[{}]",
            self.auth.debug_summary()
        );
        let envelope = WireBatchEnvelope {
            batch_request_id,
            rest_requests: requests
                .iter()
                .map(|r| WireBatchGetItem {
                    id: &r.id,
                    method: "GET",
                    url: sanitize_batch_sub_url(&r.url),
                    exclude_response_headers: true,
                    headers: [WireBatchHeader {
                        name: "Accept".to_string(),
                        value: "application/json".to_string(),
                    }],
                })
                .collect(),
        };

        let started = Instant::now();
        let req = self.auth.apply(self.http.post(url).json(&envelope))?;
        let resp = req.send().await.map_err(|e| self.map_reqwest_error(e))?;
        crate::debug_log!(
            "http",
            "POST /api/now/batch -> HTTP {} ({}ms)",
            resp.status(),
            started.elapsed().as_millis()
        );
        let raw_val: serde_json::Value = self.decode_json_response(resp, "/api/now/batch").await?;
        let target_val = raw_val
            .get("result")
            .filter(|v| v.is_object())
            .unwrap_or(&raw_val);
        let batch: BatchResponse = serde_json::from_value(target_val.clone()).map_err(|e| {
            SncfrError::NetworkOrInstance {
                message: format!("Failed to parse BatchResponse from '/api/now/batch': {e}"),
                status: Some(200),
                remediation: None,
            }
        })?;
        for sub in &batch.serviced_requests {
            crate::debug_log!(
                "batch",
                "Sub-request '{}' -> status={} time={:?}ms",
                sub.id,
                sub.status_code,
                sub.execution_time
            );
        }
        Ok(batch)
    }

    /// Executes multiple read-only (`GET`) sub-requests via `/api/now/batch`, automatically degrading
    /// to concurrent individual `GET` requests if `/api/now/batch` is ACL-restricted or unavailable on the instance.
    pub async fn batch_get_with_fallback(
        &self,
        batch_request_id: &str,
        requests: &[BatchGetSubRequest],
    ) -> Result<BatchResponse, SncfrError> {
        match self.batch_get(batch_request_id, requests).await {
            Ok(batch) => Ok(batch),
            Err(SncfrError::AuthExpired { instance }) => Err(SncfrError::AuthExpired { instance }),
            Err(SncfrError::AuthRequired { profile }) => Err(SncfrError::AuthRequired { profile }),
            Err(err) => {
                crate::debug_log!(
                    "batch",
                    "/api/now/batch unavailable ({err}); falling back to {} concurrent GET requests",
                    requests.len()
                );
                let futures = requests
                    .iter()
                    .map(|sub_req| self.execute_fallback_sub_get(sub_req));
                let results = futures_util::future::join_all(futures).await;
                let mut serviced_requests = Vec::with_capacity(results.len());
                for res in results {
                    serviced_requests.push(res?);
                }
                Ok(BatchResponse {
                    batch_request_id: Some(batch_request_id.to_string()),
                    serviced_requests,
                    unserviced_requests: Vec::new(),
                })
            }
        }
    }

    async fn execute_fallback_sub_get(
        &self,
        sub_req: &BatchGetSubRequest,
    ) -> Result<ServicedSubResponse, SncfrError> {
        let sanitized = sanitize_batch_sub_url(&sub_req.url);
        let url = self.endpoint_url(&sanitized)?;
        crate::debug_log!("http", "GET (batch-fallback '{}') {url}", sub_req.id);
        let started = Instant::now();
        let req = self.auth.apply(self.http.get(url))?;
        let resp = req.send().await.map_err(|e| self.map_reqwest_error(e))?;
        let status = resp.status();
        let code = status.as_u16();
        let elapsed_ms = started.elapsed().as_millis() as u64;
        crate::debug_log!(
            "http",
            "GET (batch-fallback '{}') -> HTTP {status} ({elapsed_ms}ms)",
            sub_req.id
        );

        if code == 401 || status.is_redirection() {
            return Err(SncfrError::AuthExpired {
                instance: self.base_url.as_str().trim_end_matches('/').to_string(),
            });
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if status.is_success() && content_type.contains("text/html") {
            return Err(SncfrError::AuthExpired {
                instance: self.base_url.as_str().trim_end_matches('/').to_string(),
            });
        }

        let status_text = status.canonical_reason().map(str::to_string);
        let bytes = resp.bytes().await.map_err(|e| self.map_reqwest_error(e))?;
        let encoded_body = BASE64_STANDARD.encode(&bytes);
        let error_message = if !status.is_success() {
            let text = String::from_utf8_lossy(&bytes);
            extract_servicenow_error_detail(&text).or_else(|| status_text.clone())
        } else {
            None
        };

        Ok(ServicedSubResponse {
            id: sub_req.id.clone(),
            status_code: code,
            status_text,
            body: Some(encoded_body),
            error_message,
            execution_time: Some(elapsed_ms),
        })
    }

    fn endpoint_url(&self, path: &str) -> Result<Url, SncfrError> {
        self.base_url
            .join(path)
            .map_err(|e| SncfrError::InvalidArgs {
                message: format!("Invalid endpoint path '{path}': {e}"),
                remediation: None,
            })
    }

    fn map_reqwest_error(&self, err: reqwest::Error) -> SncfrError {
        SncfrError::NetworkOrInstance {
            message: format!(
                "Request to '{}' failed: {err}",
                self.base_url.as_str().trim_end_matches('/')
            ),
            status: err.status().map(|s| s.as_u16()),
            remediation: Some(
                "Check network connectivity, VPN/proxy settings, and run `sncfr doctor`."
                    .to_string(),
            ),
        }
    }

    async fn decode_json_response<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
        resource: &str,
    ) -> Result<T, SncfrError> {
        let status = resp.status();
        if !status.is_success() {
            return Err(self.map_error_status(resp, resource).await);
        }

        // Guard against SSO/IdP 200 OK HTML login pages when session cookies expire
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if content_type.contains("text/html") {
            return Err(SncfrError::AuthExpired {
                instance: self.base_url.as_str().trim_end_matches('/').to_string(),
            });
        }

        let bytes = resp.bytes().await.map_err(|e| self.map_reqwest_error(e))?;
        serde_json::from_slice(&bytes).map_err(|e| SncfrError::NetworkOrInstance {
            message: format!("Failed to deserialize JSON from '{resource}': {e}"),
            status: Some(status.as_u16()),
            remediation: None,
        })
    }

    async fn map_error_status(&self, resp: reqwest::Response, resource: &str) -> SncfrError {
        let status = resp.status();
        let code = status.as_u16();
        let instance = self.base_url.as_str().trim_end_matches('/').to_string();
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body_text = resp.text().await.unwrap_or_default();
        let body_preview: String = body_text.chars().take(300).collect();

        crate::debug_log!(
            "http",
            "Error response on '{resource}': HTTP {status} location={location:?} body_preview={body_preview:?}"
        );

        // Redirects (301/302/307 to /login.do or IdP) or 401 indicate expired/invalid auth
        if code == 401 || status.is_redirection() {
            return SncfrError::AuthExpired { instance };
        }

        let sn_detail = extract_servicenow_error_detail(&body_text).unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string()
        });

        match code {
            403 => SncfrError::AclForbidden {
                resource: resource.to_string(),
                details: sn_detail,
            },
            404 => SncfrError::NotFound {
                identifier: resource.to_string(),
                table: None,
            },
            429 => SncfrError::NetworkOrInstance {
                message: format!(
                    "Rate limited (429 Too Many Requests) on '{resource}': {sn_detail}"
                ),
                status: Some(429),
                remediation: Some("Wait briefly and retry the command.".to_string()),
            },
            _ => SncfrError::NetworkOrInstance {
                message: format!("HTTP {code} on '{resource}': {sn_detail}"),
                status: Some(code),
                remediation: None,
            },
        }
    }
}

/// Mutating ServiceNow HTTP client (`docs/SPEC.md` Section 4.1).
///
/// Can only be constructed by presenting a [`WritePermit`]. Exposes `POST`, `PATCH`, and
/// attachment upload operations. Intentionally exposes **no `DELETE` operations**.
#[derive(Debug)]
pub struct MutatingClient {
    read_only: ReadOnlyClient,
    _permit: WritePermit,
}

impl MutatingClient {
    /// Constructs a [`MutatingClient`] from a [`ReadOnlyClient`] and a verified [`WritePermit`].
    pub const fn new(read_only: ReadOnlyClient, permit: WritePermit) -> Self {
        Self {
            read_only,
            _permit: permit,
        }
    }

    /// Borrows the underlying [`ReadOnlyClient`].
    pub const fn read_only(&self) -> &ReadOnlyClient {
        &self.read_only
    }

    /// Sends an authenticated `POST` request with a JSON payload (e.g., creating a ticket or catalog order).
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        body: &B,
    ) -> Result<T, SncfrError> {
        let url = self.read_only.endpoint_url(path)?;
        let req = self
            .read_only
            .auth
            .apply(self.read_only.http.post(url).query(query).json(body))?;
        let resp = req
            .send()
            .await
            .map_err(|e| self.read_only.map_reqwest_error(e))?;
        self.read_only.decode_json_response(resp, path).await
    }

    /// Sends an authenticated `PATCH` request with a JSON payload (e.g., updating ticket fields, comments, or work notes).
    pub async fn patch_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        body: &B,
    ) -> Result<T, SncfrError> {
        let url = self.read_only.endpoint_url(path)?;
        let req = self
            .read_only
            .auth
            .apply(self.read_only.http.patch(url).query(query).json(body))?;
        let resp = req
            .send()
            .await
            .map_err(|e| self.read_only.map_reqwest_error(e))?;
        self.read_only.decode_json_response(resp, path).await
    }

    /// Uploads a binary attachment to a ticket record via `POST /api/now/attachment/file`.
    pub async fn upload_attachment<T: DeserializeOwned>(
        &self,
        table_name: &str,
        table_sys_id: &str,
        file_name: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<T, SncfrError> {
        let path = "/api/now/attachment/file";
        let url = self.read_only.endpoint_url(path)?;
        let query = [
            ("table_name", table_name),
            ("table_sys_id", table_sys_id),
            ("file_name", file_name),
        ];
        let req = self.read_only.auth.apply(
            self.read_only
                .http
                .post(url)
                .query(&query)
                .header(CONTENT_TYPE, content_type)
                .body(bytes),
        )?;
        let resp = req
            .send()
            .await
            .map_err(|e| self.read_only.map_reqwest_error(e))?;
        self.read_only.decode_json_response(resp, path).await
    }
}

fn sanitize_batch_sub_url(raw: &str) -> String {
    raw.replace('^', "%5E").replace(' ', "%20")
}

fn extract_servicenow_error_detail(body: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(body).ok()?;
    let err_obj = val.get("error")?;
    let msg = err_obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let detail = err_obj.get("detail").and_then(|v| v.as_str()).unwrap_or("");
    match (msg.is_empty(), detail.is_empty()) {
        (true, true) => None,
        (false, true) => Some(msg.to_string()),
        (true, false) => Some(detail.to_string()),
        (false, false) => Some(format!("{msg} ({detail})")),
    }
}

/// Extracts the raw internal `value` of a field from a ServiceNow JSON record (handles both
/// `sysparm_display_value=all` `{ display_value, value }` objects and plain string scalars).
pub fn extract_field_value(record: &serde_json::Value, field: &str) -> Option<String> {
    let f = record.get(field)?;
    if let Some(s) = f.as_str() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
        return None;
    }
    if let Some(obj) = f.as_object() {
        if let Some(v) = obj.get("value").and_then(|v| v.as_str()) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(dv) = obj.get("display_value").and_then(|v| v.as_str()) {
            let trimmed = dv.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Extracts the human-readable `display_value` of a field from a ServiceNow JSON record.
pub fn extract_field_display(record: &serde_json::Value, field: &str) -> Option<String> {
    let f = record.get(field)?;
    if let Some(s) = f.as_str() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
        return None;
    }
    if let Some(obj) = f.as_object() {
        if let Some(dv) = obj.get("display_value").and_then(|v| v.as_str()) {
            let trimmed = dv.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(v) = obj.get("value").and_then(|v| v.as_str()) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Extracts `(display_value, value)` from a ServiceNow JSON record field if non-empty.
pub fn extract_field_pair(record: &serde_json::Value, field: &str) -> Option<(String, String)> {
    let disp = extract_field_display(record, field)?;
    let val = extract_field_value(record, field).unwrap_or_else(|| disp.clone());
    Some((disp, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, AuthMethod, ProfileConfig};
    use clap::Parser;
    use std::collections::BTreeMap;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn write_permit_enforces_dry_run_and_read_only_locks() {
        let mut cfg = AppConfig {
            default_profile: Some("prod".to_string()),
            profiles: BTreeMap::new(),
        };
        cfg.profiles.insert(
            "prod".to_string(),
            ProfileConfig {
                instance: "https://mycompany.service-now.com".to_string(),
                auth_method: AuthMethod::Sso,
                username: None,
                read_only: false,
                views: BTreeMap::new(),
                ..Default::default()
            },
        );

        // 1. Dry-run invocation (no --write): returns Ok(None)
        let dry_cli =
            Cli::try_parse_from(["sncfr", "comment", "INC0010042", "Hello"]).expect("parse");
        let prof = cfg.resolve_profile(&dry_cli).expect("profile");
        assert!(WritePermit::issue(&dry_cli, Some(&prof)).unwrap().is_none());

        // 2. Explicit --write with unlocked profile: returns Ok(Some(WritePermit))
        let write_cli = Cli::try_parse_from(["sncfr", "comment", "INC0010042", "Hello", "--write"])
            .expect("parse");
        assert!(
            WritePermit::issue(&write_cli, Some(&prof))
                .unwrap()
                .is_some()
        );

        // 3. Explicit --write with profile read_only = true: returns Err(ReadOnlyLocked) (exit code 6)
        cfg.profiles.get_mut("prod").unwrap().read_only = true;
        let locked_prof = cfg.resolve_profile(&write_cli).expect("locked profile");
        let err = WritePermit::issue(&write_cli, Some(&locked_prof)).unwrap_err();
        assert_eq!(err.code().exit_code(), 6);
    }

    #[tokio::test]
    async fn read_only_client_sends_sso_headers_and_maps_status_codes() {
        let server = MockServer::start().await;
        let base_url = Url::parse(&server.uri()).expect("mock url");
        let client = ReadOnlyClient::new(
            base_url,
            ClientAuth::SsoSession {
                cookie: "JSESSIONID=abc; glide_user_route=glide.123".to_string(),
                user_token: Some("g_ck_token_xyz".to_string()),
            },
        )
        .expect("client");

        // 200 OK JSON
        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .and(header(
                "Cookie",
                "JSESSIONID=abc; glide_user_route=glide.123",
            ))
            .and(header("X-UserToken", "g_ck_token_xyz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": [{ "number": "INC0010042" }] })),
            )
            .mount(&server)
            .await;

        let val: serde_json::Value = client
            .get_json("/api/now/table/incident", &[("sysparm_limit", "1")])
            .await
            .expect("200 OK");
        assert_eq!(val["result"][0]["number"], "INC0010042");

        // 403 Forbidden -> AclForbidden (exit code 4)
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_journal_field"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {
                    "message": "Insufficient rights to query records",
                    "detail": "Access to api 'api/now/table/sys_journal_field' has been refused"
                }
            })))
            .mount(&server)
            .await;

        let err_403 = client
            .get_json::<serde_json::Value>("/api/now/table/sys_journal_field", &[])
            .await
            .unwrap_err();
        assert_eq!(err_403.code().exit_code(), 4);

        // 302 Redirect to IdP / login.do -> AuthExpired (exit code 3)
        Mock::given(method("GET"))
            .and(path("/api/now/table/task"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", "https://idp.example.com/sso"),
            )
            .mount(&server)
            .await;

        let err_302 = client
            .get_json::<serde_json::Value>("/api/now/table/task", &[])
            .await
            .unwrap_err();
        assert_eq!(err_302.code().exit_code(), 3);
    }

    #[tokio::test]
    async fn batch_get_decodes_multiline_base64_and_handles_partial_acl_403() {
        let server = MockServer::start().await;
        let base_url = Url::parse(&server.uri()).expect("mock url");
        let client = ReadOnlyClient::new(
            base_url,
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "secret-key".to_string(),
            },
        )
        .expect("client");

        let ticket_json = r#"{"result":[{"number":"INC0010042","sys_id":"abc"}]}"#;
        let b64_ticket = BASE64_STANDARD.encode(ticket_json);
        // Insert a newline in the middle of base64 to simulate ServiceNow's wrapped base64 output
        let wrapped_b64 = format!("{}\n{}", &b64_ticket[..12], &b64_ticket[12..]);

        Mock::given(method("POST"))
            .and(path("/api/now/batch"))
            .and(header("x-sn-apikey", "secret-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "batch_request_id": "dossier-1",
                "serviced_requests": [
                    {
                        "id": "ticket",
                        "status_code": 200,
                        "status_text": "OK",
                        "body": wrapped_b64,
                        "execution_time": 9
                    },
                    {
                        "id": "journal",
                        "status_code": 403,
                        "status_text": "Forbidden",
                        "error_message": "ACL restricted",
                        "execution_time": 2
                    }
                ],
                "unserviced_requests": []
            })))
            .mount(&server)
            .await;

        let batch = client
            .batch_get(
                "dossier-1",
                &[
                    BatchGetSubRequest::new("ticket", "/api/now/table/incident?sysparm_limit=1"),
                    BatchGetSubRequest::new(
                        "journal",
                        "/api/now/table/sys_journal_field?sysparm_limit=10",
                    ),
                ],
            )
            .await
            .expect("batch_get succeeds even when a sub-request is 403");

        let ticket_sub = batch.get("ticket").expect("ticket sub");
        assert!(ticket_sub.is_success());
        let decoded: serde_json::Value = ticket_sub.decode_json().expect("decode ticket json");
        assert_eq!(decoded["result"][0]["number"], "INC0010042");

        let journal_sub = batch.get("journal").expect("journal sub");
        assert!(journal_sub.is_forbidden());
        let journal_err = journal_sub.decode_json::<serde_json::Value>().unwrap_err();
        assert_eq!(journal_err.code().exit_code(), 4);
    }

    #[tokio::test]
    async fn mutating_client_executes_patch_and_attachment_upload_with_write_permit() {
        let server = MockServer::start().await;
        let base_url = Url::parse(&server.uri()).expect("mock url");
        let ro_client = ReadOnlyClient::new(
            base_url,
            ClientAuth::Bearer {
                token: "oauth-token".to_string(),
            },
        )
        .expect("client");

        let cli = Cli::try_parse_from(["sncfr", "comment", "INC0010042", "Fixed", "--write"])
            .expect("parse");
        let permit = WritePermit::issue(&cli, None)
            .expect("no lock")
            .expect("write permit issued");
        let mutating = ro_client.into_mutating(permit);

        Mock::given(method("PATCH"))
            .and(path("/api/now/table/incident/sys123"))
            .and(header("Authorization", "Bearer oauth-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "sys_id": "sys123" } })),
            )
            .mount(&server)
            .await;

        let updated: serde_json::Value = mutating
            .patch_json(
                "/api/now/table/incident/sys123",
                &[],
                &serde_json::json!({ "comments": "Fixed" }),
            )
            .await
            .expect("patch_json");
        assert_eq!(updated["result"]["sys_id"], "sys123");

        Mock::given(method("POST"))
            .and(path("/api/now/attachment/file"))
            .and(query_param("table_name", "incident"))
            .and(query_param("table_sys_id", "sys123"))
            .and(query_param("file_name", "crash.log"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({ "result": { "file_name": "crash.log" } })),
            )
            .mount(&server)
            .await;

        let uploaded: serde_json::Value = mutating
            .upload_attachment(
                "incident",
                "sys123",
                "crash.log",
                "text/plain",
                b"panic at line 42".to_vec(),
            )
            .await
            .expect("upload_attachment");
        assert_eq!(uploaded["result"]["file_name"], "crash.log");
    }
}
