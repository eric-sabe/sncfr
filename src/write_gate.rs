//! The write gate (ADR-0002 amendment, SAFE-3, SAFE-4, NA-2, NA-17).
//!
//! The only way to send a mutating request is:
//!
//! 1. build a [`VerifiedMutation`] from *resolved* values ([`ResolvedValue`] has no public
//!    constructor, so nothing reaches a payload without going through resolution);
//! 2. [`MutatingClient::authorize`] it, which runs the same [`VerifiedMutation::check`] the
//!    dry-run uses and refuses (exit 8) any `UNVERIFIABLE` field not named in
//!    `--allow-unverified`;
//! 3. [`MutatingClient::send`] the resulting [`AuthorizedPayload`], which also compares what the
//!    instance returned with what was sent (exit 9 when a field silently wasn't applied).
//!
//! `AuthorizedPayload` and `VerifiedMutation` can't be built outside this module:
//!
//! ```compile_fail
//! let _ = sncfr::write_gate::AuthorizedPayload { };
//! ```
//!
//! ```compile_fail
//! let _ = sncfr::write_gate::VerifiedMutation { };
//! ```
//!
//! This file is a child module of `client` (see `#[path]` there), so it can reach the client's
//! private HTTP methods while no other module can.

use super::{MutatingClient, extract_field_value};
use crate::error::SncfrError;
use crate::resolve_value::ResolvedValue;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// A value that could not be confirmed against an active pack or instance metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiableField {
    pub field: String,
    pub input: String,
    pub would_send: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<String>,
}

impl UnverifiableField {
    pub fn from_resolved(field: &str, input: &str, resolved: &ResolvedValue) -> Option<Self> {
        resolved.unverifiable().map(|reason| Self {
            field: field.to_string(),
            input: input.to_string(),
            would_send: resolved.value().to_string(),
            reason: reason.as_str().to_string(),
            candidates: resolved
                .candidates()
                .iter()
                .map(|(v, l)| format!("{l} ({v})"))
                .collect(),
            suggested: resolved.suggested().map(str::to_string),
        })
    }
}

/// A field the instance accepted but did not apply (unknown field, field-level write ACL, or a
/// business rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotApplied {
    pub field: String,
    pub sent: String,
    pub returned: String,
}

/// `--allow-unverified` for this invocation: explicit, lower-cased field names only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    names: BTreeSet<String>,
}

impl AllowList {
    /// Parses `--allow-unverified` values. Wildcards are refused (exit 2).
    pub fn parse(raw: &[String]) -> Result<Self, SncfrError> {
        let mut names = BTreeSet::new();
        for name in raw
            .iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
        {
            if name == "*" || name == "all" || name.contains('*') {
                return Err(SncfrError::InvalidArgs {
                    message: "--allow-unverified needs explicit field names".to_string(),
                    remediation: Some(
                        "Name each field, e.g. `--allow-unverified u_tier` (catalog variables: `var:<name>`)."
                            .to_string(),
                    ),
                });
            }
            names.insert(name);
        }
        Ok(Self { names })
    }

    pub fn contains(&self, field: &str) -> bool {
        self.names.contains(&field.to_ascii_lowercase())
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.names.iter()
    }
}

static ALLOW: OnceLock<AllowList> = OnceLock::new();

/// Installs this invocation's `--allow-unverified` list (once, from `main`).
pub fn install_allow_list(list: AllowList) -> bool {
    ALLOW.set(list).is_ok()
}

/// This invocation's `--allow-unverified` list (empty unless installed).
pub fn allow_list() -> &'static AllowList {
    ALLOW.get_or_init(AllowList::default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Post,
    Patch,
}

/// Where a mutation goes. The path is validated when the target is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    method: Method,
    path: String,
}

impl Target {
    /// `PATCH /api/now/table/<table>/<sys_id>`.
    pub fn patch_record(table: &str, sys_id: &str) -> Result<Self, SncfrError> {
        let path = format!("/api/now/table/{table}/{sys_id}");
        crate::untrusted::check_api_path(&path)?;
        Ok(Self {
            method: Method::Patch,
            path,
        })
    }

    /// `POST /api/now/table/<table>` (create a record).
    pub fn post_table(table: &str) -> Result<Self, SncfrError> {
        let path = format!("/api/now/table/{table}");
        crate::untrusted::check_api_path(&path)?;
        Ok(Self {
            method: Method::Post,
            path,
        })
    }

    /// `POST /api/sn_sc/servicecatalog/items/<item>/order_now`.
    pub fn catalog_order(item_sys_id: &str) -> Result<Self, SncfrError> {
        if !crate::untrusted::is_sys_id(item_sys_id) {
            return Err(SncfrError::InvalidArgs {
                message: format!(
                    "'{}' is not a catalog item sys_id",
                    crate::untrusted::inline(item_sys_id)
                ),
                remediation: None,
            });
        }
        Ok(Self {
            method: Method::Post,
            path: format!("/api/sn_sc/servicecatalog/items/{item_sys_id}/order_now"),
        })
    }
}

#[derive(Debug)]
enum Body {
    /// A record write; `checked` fields are compared with the response afterwards (NA-17).
    Record(Map<String, Value>),
    /// Any other JSON body (catalog order); the response is not a record.
    Json(Value),
    File {
        query: Vec<(String, String)>,
        content_type: String,
        bytes: Vec<u8>,
    },
}

/// A mutation whose every value came out of resolution. Built only here.
#[derive(Debug)]
pub struct VerifiedMutation {
    target: Target,
    body: Body,
    unverifiable: Vec<UnverifiableField>,
}

/// `(field, input as typed, resolved value)`.
pub type ResolvedField = (String, String, ResolvedValue);

impl VerifiedMutation {
    /// A record write (`update`, `create`, `comment`, `note`, approval state) from resolved fields.
    pub fn record(target: Target, fields: &[ResolvedField]) -> Self {
        let mut body = Map::new();
        let mut unverifiable = Vec::new();
        for (field, input, resolved) in fields {
            body.insert(field.clone(), Value::String(resolved.value().to_string()));
            unverifiable.extend(UnverifiableField::from_resolved(field, input, resolved));
        }
        Self {
            target,
            body: Body::Record(body),
            unverifiable,
        }
    }

    /// A catalog order: `base` carries the request envelope (quantity, requested_for); resolved
    /// variables go under `variables`.
    pub fn catalog_order(target: Target, mut base: Value, variables: &[ResolvedField]) -> Self {
        let mut vars = Map::new();
        let mut unverifiable = Vec::new();
        for (name, input, resolved) in variables {
            vars.insert(name.clone(), Value::String(resolved.value().to_string()));
            unverifiable.extend(UnverifiableField::from_resolved(
                &format!("var:{name}"),
                input,
                resolved,
            ));
        }
        base["variables"] = Value::Object(vars);
        Self {
            target,
            body: Body::Json(base),
            unverifiable,
        }
    }

    /// An attachment upload to `table`/`sys_id`.
    pub fn attachment(
        table: &str,
        sys_id: &str,
        file_name: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Self, SncfrError> {
        crate::untrusted::check_api_path(&format!("/api/now/table/{table}/{sys_id}"))?;
        Ok(Self {
            target: Target {
                method: Method::Post,
                path: "/api/now/attachment/file".to_string(),
            },
            body: Body::File {
                query: vec![
                    ("table_name".to_string(), table.to_string()),
                    ("table_sys_id".to_string(), sys_id.to_string()),
                    ("file_name".to_string(), file_name.to_string()),
                ],
                content_type: content_type.to_string(),
                bytes,
            },
            unverifiable: Vec::new(),
        })
    }

    /// Every unverifiable field, allowed or not.
    pub fn unverifiable(&self) -> &[UnverifiableField] {
        &self.unverifiable
    }

    /// Unverifiable fields not covered by `allow`.
    pub fn blocking(&self, allow: &AllowList) -> Vec<UnverifiableField> {
        self.unverifiable
            .iter()
            .filter(|u| !allow.contains(&u.field))
            .cloned()
            .collect()
    }

    /// The single check used by both dry-run and `--write` (NA-2).
    pub fn check(&self, allow: &AllowList) -> Result<(), SncfrError> {
        let blocking = self.blocking(allow);
        if blocking.is_empty() {
            Ok(())
        } else {
            Err(SncfrError::Unverifiable { fields: blocking })
        }
    }
}

/// A mutation cleared to send. Not `Clone`, no public fields, consumed by [`MutatingClient::send`].
#[derive(Debug)]
pub struct AuthorizedPayload {
    target: Target,
    body: Body,
}

/// What a write returned, after the post-write check.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteOutcome {
    pub response: Value,
    pub not_applied: Vec<NotApplied>,
    pub unconfirmed: Vec<String>,
}

/// Fields compared after a record write: journal fields aren't stored on the record itself.
fn is_journal(field: &str) -> bool {
    matches!(field, "comments" | "work_notes" | "comments_and_work_notes")
}

impl MutatingClient {
    /// Clears every mutation of an invocation *before* the first request is sent: if any one has
    /// a blocking unverifiable field, nothing is sent (NA-2).
    pub fn authorize(
        &self,
        mutations: Vec<VerifiedMutation>,
        allow: &AllowList,
    ) -> Result<Vec<AuthorizedPayload>, SncfrError> {
        let blocking: Vec<UnverifiableField> =
            mutations.iter().flat_map(|m| m.blocking(allow)).collect();
        if !blocking.is_empty() {
            return Err(SncfrError::Unverifiable { fields: blocking });
        }
        Ok(mutations
            .into_iter()
            .map(|m| AuthorizedPayload {
                target: m.target,
                body: m.body,
            })
            .collect())
    }

    /// Sends one authorized mutation and compares a record write's response with what was sent.
    pub async fn send(&self, payload: AuthorizedPayload) -> Result<WriteOutcome, SncfrError> {
        let AuthorizedPayload { target, body } = payload;
        let display = [("sysparm_display_value", "all")];
        match body {
            Body::Record(fields) => {
                let response: Value = match target.method {
                    Method::Patch => self.patch_json(&target.path, &display, &fields).await?,
                    Method::Post => self.post_json(&target.path, &display, &fields).await?,
                };
                let record = response.get("result").unwrap_or(&response);
                let mut not_applied = Vec::new();
                let mut unconfirmed = Vec::new();
                for (field, sent) in &fields {
                    if is_journal(field) {
                        continue;
                    }
                    let sent = sent.as_str().unwrap_or_default();
                    match extract_field_value(record, field) {
                        Some(returned) if returned.trim() != sent.trim() => {
                            not_applied.push(NotApplied {
                                field: field.clone(),
                                sent: sent.to_string(),
                                returned,
                            });
                        }
                        Some(_) => {}
                        None => unconfirmed.push(field.clone()),
                    }
                }
                Ok(WriteOutcome {
                    response,
                    not_applied,
                    unconfirmed,
                })
            }
            Body::Json(json) => {
                let response: Value = self.post_json(&target.path, &[], &json).await?;
                Ok(WriteOutcome {
                    response,
                    not_applied: Vec::new(),
                    unconfirmed: Vec::new(),
                })
            }
            Body::File {
                query,
                content_type,
                bytes,
            } => {
                let q: BTreeMap<&str, &str> = query
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                let response: Value = self
                    .upload_attachment(
                        q.get("table_name").copied().unwrap_or_default(),
                        q.get("table_sys_id").copied().unwrap_or_default(),
                        q.get("file_name").copied().unwrap_or_default(),
                        &content_type,
                        bytes,
                    )
                    .await?;
                Ok(WriteOutcome {
                    response,
                    not_applied: Vec::new(),
                    unconfirmed: Vec::new(),
                })
            }
        }
    }
}
