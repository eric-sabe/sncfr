use serde::Serialize;
use std::process::ExitCode;
use thiserror::Error;

/// Canonical machine-readable error codes and exit statuses defined in `docs/SPEC.md` Section 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Exit code 2: Invalid CLI arguments, unknown field, invalid choice value, or unresolved reference.
    InvalidArgs,
    /// Exit code 2: Field or choice validation error against instance schema.
    ValidationError,
    /// Exit code 3: Active session has expired.
    AuthExpired,
    /// Exit code 3: No authentication session configured for target profile/instance.
    AuthRequired,
    /// Exit code 4: Authenticated user lacks ServiceNow ACL permissions for the target resource.
    AclForbidden,
    /// Exit code 5: Ticket number or record `sys_id` was not found (or hidden by query rules/ACLs).
    NotFound,
    /// Exit code 6: `--write` was attempted while `SNCFR_READ_ONLY=1` or profile `read_only = true` is active.
    ReadOnlyLocked,
    /// Exit code 7: Network, TLS, rate-limit (429), or ServiceNow 5xx instance error.
    NetworkOrInstanceError,
    /// Exit code 2: An Instance Pack failed to parse or validate (ADR-0004).
    PackInvalid,
    /// Exit code 2: A value would change the structure of an encoded query (NA-13).
    InvalidQueryValue,
    /// Exit code 2: The merged Instance Pack does not list this instance (NA-14).
    PackNotForInstance,
    /// Exit code 2: A user/group/approval reference matched more than one record (NA-3).
    AmbiguousReference,
    /// Exit code 7: A write failed after it may have been sent; its outcome is unknown (NA-7).
    WriteOutcomeUnknown,
    /// Exit code 8: A value could not be confirmed against a pack or instance metadata; nothing
    /// was written (SAFE-3).
    Unverifiable,
    /// Exit code 9: The instance accepted a write but did not apply some fields (NA-17).
    WriteNotApplied,
}

impl ErrorCode {
    /// Deterministic exit code per `docs/SPEC.md` Section 6.2.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArgs
            | Self::ValidationError
            | Self::PackInvalid
            | Self::InvalidQueryValue
            | Self::PackNotForInstance
            | Self::AmbiguousReference => 2,
            Self::AuthExpired | Self::AuthRequired => 3,
            Self::AclForbidden => 4,
            Self::NotFound => 5,
            Self::ReadOnlyLocked => 6,
            Self::NetworkOrInstanceError | Self::WriteOutcomeUnknown => 7,
            Self::Unverifiable => 8,
            Self::WriteNotApplied => 9,
        }
    }

    /// Canonical string identifier for structured error envelopes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgs => "INVALID_ARGS",
            Self::ValidationError => "VALIDATION_ERROR",
            Self::AuthExpired => "AUTH_EXPIRED",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AclForbidden => "ACL_FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::ReadOnlyLocked => "READ_ONLY_LOCKED",
            Self::NetworkOrInstanceError => "NETWORK_OR_INSTANCE_ERROR",
            Self::PackInvalid => "PACK_INVALID",
            Self::InvalidQueryValue => "INVALID_QUERY_VALUE",
            Self::PackNotForInstance => "PACK_NOT_FOR_INSTANCE",
            Self::AmbiguousReference => "AMBIGUOUS_REFERENCE",
            Self::WriteOutcomeUnknown => "WRITE_OUTCOME_UNKNOWN",
            Self::Unverifiable => "UNVERIFIABLE",
            Self::WriteNotApplied => "WRITE_NOT_APPLIED",
        }
    }
}

/// Primary domain error type for `sncfr`.
#[derive(Debug, Error)]
pub enum SncfrError {
    #[error("{message}")]
    InvalidArgs {
        message: String,
        remediation: Option<String>,
    },

    #[error("{message}")]
    Validation {
        message: String,
        valid_choices: Vec<String>,
        remediation: Option<String>,
    },

    #[error("ServiceNow session for '{instance}' has expired or is invalid")]
    AuthExpired { instance: String },

    #[error("No active authentication session found for profile '{profile}'")]
    AuthRequired { profile: String },

    #[error("Access denied (403 Forbidden) by ServiceNow ACLs on '{resource}': {details}")]
    AclForbidden { resource: String, details: String },

    #[error("Record or ticket '{identifier}' not found")]
    NotFound {
        identifier: String,
        table: Option<String>,
    },

    #[error(
        "No pending approval on '{identifier}' is assigned to you or your groups (found: {})",
        .found.join("; ")
    )]
    NoActionableApproval {
        identifier: String,
        found: Vec<String>,
    },

    #[error("Mutation blocked: profile or environment is locked to read-only mode ({reason})")]
    ReadOnlyLocked { reason: String },

    #[error(
        "Not written: {} field(s) could not be verified ({})",
        .fields.len(),
        .fields.iter().map(|f| f.field.as_str()).collect::<Vec<_>>().join(", ")
    )]
    Unverifiable {
        fields: Vec<crate::client::write_gate::UnverifiableField>,
    },

    #[error(
        "The record was partly updated: the instance did not apply {}",
        .not_applied.iter().map(|f| f.field.as_str()).collect::<Vec<_>>().join(", ")
    )]
    WriteNotApplied {
        not_applied: Vec<crate::client::write_gate::NotApplied>,
    },

    #[error("--{kind} \"{input}\" matches {} {kind}s ({detail}). Nothing was written.", .candidates.len())]
    AmbiguousReference {
        kind: String,
        input: String,
        detail: String,
        candidates: Vec<String>,
        suggestion: Option<String>,
    },

    #[error("Request to '{resource}' timed out after {timeout_secs}s")]
    TimedOut { resource: String, timeout_secs: u64 },

    #[error("Rate limited (429) on '{resource}'; retry after {retry_after_secs}s")]
    RateLimited {
        resource: String,
        retry_after_secs: u64,
    },

    #[error(
        "The write to '{resource}' may or may not have been applied (timeout or connection reset after sending)"
    )]
    WriteOutcomeUnknown { resource: String },

    #[error("Instance Pack '{pack}' does not list instance '{instance}' (`instances = [...]`)")]
    PackNotForInstance { pack: String, instance: String },

    #[error("Value '{value}' cannot be used in a ServiceNow query: {reason}")]
    InvalidQueryValue { value: String, reason: String },

    #[error("Invalid Instance Pack '{pack}':\n  {}", .problems.join("\n  "))]
    PackInvalid { pack: String, problems: Vec<String> },

    #[error("Network or ServiceNow instance error: {message}")]
    NetworkOrInstance {
        message: String,
        status: Option<u16>,
        remediation: Option<String>,
    },
}

/// Structured error envelope emitted to agents and JSON consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub exit_code: u8,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub valid_choices: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unverifiable_fields: Vec<crate::client::write_gate::UnverifiableField>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_applied: Vec<crate::client::write_gate::NotApplied>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

impl SncfrError {
    /// Returns the [`ErrorCode`] classification for this error.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgs { .. } => ErrorCode::InvalidArgs,
            Self::Validation { .. } => ErrorCode::ValidationError,
            Self::AuthExpired { .. } => ErrorCode::AuthExpired,
            Self::AuthRequired { .. } => ErrorCode::AuthRequired,
            Self::AclForbidden { .. } => ErrorCode::AclForbidden,
            Self::NotFound { .. } | Self::NoActionableApproval { .. } => ErrorCode::NotFound,
            Self::ReadOnlyLocked { .. } => ErrorCode::ReadOnlyLocked,
            Self::NetworkOrInstance { .. } => ErrorCode::NetworkOrInstanceError,
            Self::PackInvalid { .. } => ErrorCode::PackInvalid,
            Self::InvalidQueryValue { .. } => ErrorCode::InvalidQueryValue,
            Self::Unverifiable { .. } => ErrorCode::Unverifiable,
            Self::WriteNotApplied { .. } => ErrorCode::WriteNotApplied,
            Self::PackNotForInstance { .. } => ErrorCode::PackNotForInstance,
            Self::AmbiguousReference { .. } => ErrorCode::AmbiguousReference,
            Self::RateLimited { .. } | Self::TimedOut { .. } => ErrorCode::NetworkOrInstanceError,
            Self::WriteOutcomeUnknown { .. } => ErrorCode::WriteOutcomeUnknown,
        }
    }

    /// Returns the deterministic process [`ExitCode`] for this error.
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.code().exit_code())
    }

    /// Returns an actionable remediation hint for humans and AI agents.
    pub fn remediation(&self) -> Option<String> {
        match self {
            Self::InvalidArgs { remediation, .. } | Self::Validation { remediation, .. } => {
                remediation.clone()
            }
            Self::AuthExpired { .. } | Self::AuthRequired { .. } => {
                Some("Run `sncfr auth login` (or `sncfr auth import`) to authenticate.".to_string())
            }
            Self::AclForbidden { resource, .. } => Some(format!(
                "Your ServiceNow account lacks ACL access to '{resource}'. Run `sncfr doctor` to inspect your account capabilities."
            )),
            Self::NotFound { identifier, .. } => Some(format!(
                "Verify the ticket number or sys_id '{identifier}' exists and is visible to your account."
            )),
            Self::NoActionableApproval { identifier, .. } => Some(format!(
                "Only approvals in state Requested whose approver is you, or whose group is one of your assignment groups, can be approved or rejected. Run `sncfr approvals show {identifier}` to inspect them."
            )),
            Self::ReadOnlyLocked { .. } => Some(
                "Unset `SNCFR_READ_ONLY` and set `read_only = false` in config.toml if mutations are intended."
                    .to_string(),
            ),
            Self::NetworkOrInstance { remediation, .. } => remediation.clone(),
            Self::Unverifiable { .. } => Some(
                "Show the user each field's would_send value and candidates. Prefer re-running with a candidate value; pass `--allow-unverified <fields>` only when the user explicitly confirms the literal value.".to_string(),
            ),
            Self::WriteNotApplied { .. } => Some(
                "Do not retry. Report the not_applied fields to the user and check the record with `sncfr show`.".to_string(),
            ),
            Self::TimedOut { timeout_secs, .. } => Some(format!(
                "Re-run with a longer timeout, e.g. `--timeout {}`.",
                (timeout_secs * 2).clamp(2, 300)
            )),
            Self::RateLimited { retry_after_secs, .. } => Some(format!(
                "Wait {retry_after_secs}s, then retry at most once."
            )),
            Self::WriteOutcomeUnknown { .. } => Some(
                "Run `sncfr show <ticket>` to check whether the change landed before any retry. Never re-run a create or catalog order.".to_string(),
            ),
            Self::AmbiguousReference { kind, suggestion, .. } => Some(match suggestion {
                Some(s) => format!("Suggestion (not applied): {s}. Re-run with the exact {kind} name from the candidates, or its sys_id."),
                None => format!("Re-run with the exact {kind} name from the candidates, or its sys_id."),
            }),
            Self::PackNotForInstance { .. } => Some(
                "Use the pack written for this instance, or add the host to the pack's `instances` after checking its facts apply.".to_string(),
            ),
            Self::InvalidQueryValue { .. } => Some(
                "Pass the plain value only (no `^`, line breaks, or `javascript:`). For complex filters use `--query`, which is sent as you write it.".to_string(),
            ),
            Self::PackInvalid { pack, .. } => Some(format!(
                "Fix the listed problems, then check with `sncfr pack validate {pack}`."
            )),
        }
    }

    /// Converts this error into a serializable [`ErrorEnvelope`].
    pub fn to_envelope(&self) -> ErrorEnvelope {
        let code = self.code();
        let valid_choices = match self {
            Self::Validation { valid_choices, .. } => valid_choices.clone(),
            Self::AmbiguousReference { candidates, .. } => candidates.clone(),
            _ => Vec::new(),
        };
        ErrorEnvelope {
            error: ErrorDetail {
                code,
                exit_code: code.exit_code(),
                message: self.to_string(),
                remediation: self.remediation(),
                valid_choices,
                unverifiable_fields: match self {
                    Self::Unverifiable { fields } => fields.clone(),
                    _ => Vec::new(),
                },
                not_applied: match self {
                    Self::WriteNotApplied { not_applied } => not_applied.clone(),
                    _ => Vec::new(),
                },
                retry_after_secs: match self {
                    Self::RateLimited {
                        retry_after_secs, ..
                    } => Some(*retry_after_secs),
                    _ => None,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_map_to_spec_exit_codes() {
        assert_eq!(ErrorCode::InvalidArgs.exit_code(), 2);
        assert_eq!(ErrorCode::ValidationError.exit_code(), 2);
        assert_eq!(ErrorCode::AuthExpired.exit_code(), 3);
        assert_eq!(ErrorCode::AuthRequired.exit_code(), 3);
        assert_eq!(ErrorCode::AclForbidden.exit_code(), 4);
        assert_eq!(ErrorCode::NotFound.exit_code(), 5);
        assert_eq!(ErrorCode::ReadOnlyLocked.exit_code(), 6);
        assert_eq!(ErrorCode::NetworkOrInstanceError.exit_code(), 7);
    }

    #[test]
    fn auth_expired_envelope_includes_remediation_and_exit_code() {
        let err = SncfrError::AuthExpired {
            instance: "https://example.service-now.com".to_string(),
        };
        let env = err.to_envelope();
        assert_eq!(env.error.code, ErrorCode::AuthExpired);
        assert_eq!(env.error.exit_code, 3);
        assert_eq!(
            env.error.remediation.as_deref(),
            Some("Run `sncfr auth login` (or `sncfr auth import`) to authenticate.")
        );
    }

    #[test]
    fn validation_error_serializes_valid_choices() {
        let err = SncfrError::Validation {
            message: "Invalid state 'Bogus' for table 'incident'".to_string(),
            valid_choices: vec![
                "New".to_string(),
                "In Progress".to_string(),
                "Resolved".to_string(),
            ],
            remediation: Some("Use one of the valid state labels.".to_string()),
        };
        let json = serde_json::to_value(err.to_envelope()).expect("serialize error envelope");
        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["exit_code"], 2);
        assert_eq!(
            json["error"]["valid_choices"],
            serde_json::json!(["New", "In Progress", "Resolved"])
        );
    }
}
