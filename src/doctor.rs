use crate::auth::resolve_current_identity;
use crate::cache::{CachedIdentity, InstanceCache};
use crate::client::{BatchGetSubRequest, ReadOnlyClient};
use crate::config::ResolvedProfile;
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub resource: String,
    pub endpoint: String,
    pub status_code: u16,
    pub accessible: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub profile: String,
    pub instance_url: String,
    pub auth_method: String,
    pub read_only_locked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_reason: Option<String>,
    pub identity: CachedIdentity,
    pub capabilities: Vec<CapabilityCheck>,
}

const PROBED_RESOURCES: &[(&str, &str, &str)] = &[
    (
        "table:task",
        "/api/now/table/task?sysparm_limit=1&sysparm_fields=sys_id",
        "Base task table (required for cross-table search & prefix fallback)",
    ),
    (
        "table:incident",
        "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id",
        "Incident records (INC*)",
    ),
    (
        "table:sc_req_item",
        "/api/now/table/sc_req_item?sysparm_limit=1&sysparm_fields=sys_id",
        "Requested Item records (RITM*)",
    ),
    (
        "table:change_request",
        "/api/now/table/change_request?sysparm_limit=1&sysparm_fields=sys_id",
        "Change Request records (CHG*)",
    ),
    (
        "table:sys_journal_field",
        "/api/now/table/sys_journal_field?sysparm_limit=1&sysparm_fields=sys_id",
        "403 Forbidden (sncfr will fall back to inline comments_and_work_notes)",
    ),
    (
        "table:sys_number",
        "/api/now/table/sys_number?sysparm_limit=1&sysparm_fields=sys_id",
        "403 Forbidden (sncfr will use built-in ITIL prefixes + task fallback)",
    ),
    (
        "table:sys_choice",
        "/api/now/table/sys_choice?sysparm_limit=1&sysparm_fields=sys_id",
        "403 Forbidden (choice label resolution will pass raw values)",
    ),
    (
        "table:sys_dictionary",
        "/api/now/table/sys_dictionary?sysparm_limit=1&sysparm_fields=sys_id",
        "403 Forbidden (schema introspection will infer fields from records)",
    ),
    (
        "api:stats",
        "/api/now/stats/task?sysparm_count=true",
        "Aggregate API (`sncfr stats`)",
    ),
];

/// Executes `sncfr doctor`: verifies live authentication, resolves `@me` identity, and probes
/// the user's non-admin ACL capability matrix across core ServiceNow tables and REST APIs.
pub async fn execute_doctor(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
) -> Result<DoctorReport, SncfrError> {
    let identity = resolve_current_identity(client, cache, true).await?;

    let sub_requests: Vec<BatchGetSubRequest> = PROBED_RESOURCES
        .iter()
        .map(|(res, url, _)| BatchGetSubRequest::new(*res, *url))
        .collect();

    let mut capabilities = Vec::with_capacity(PROBED_RESOURCES.len() + 1);

    match client.batch_get("sncfr-doctor", &sub_requests).await {
        Ok(batch_resp) => {
            capabilities.push(CapabilityCheck {
                resource: "api:batch".to_string(),
                endpoint: "/api/now/batch".to_string(),
                status_code: 200,
                accessible: true,
                note: "Single-roundtrip Ticket Dossier enabled".to_string(),
            });

            for (res_id, endpoint, fallback_note) in PROBED_RESOURCES {
                if let Some(sub) = batch_resp.get(res_id) {
                    let accessible = sub.is_success();
                    let note = if accessible {
                        "OK".to_string()
                    } else if sub.status_code == 403 {
                        (*fallback_note).to_string()
                    } else {
                        format!("HTTP {}", sub.status_code)
                    };
                    capabilities.push(CapabilityCheck {
                        resource: (*res_id).to_string(),
                        endpoint: (*endpoint).to_string(),
                        status_code: sub.status_code,
                        accessible,
                        note,
                    });
                }
            }
        }
        Err(_) => {
            capabilities.push(CapabilityCheck {
                resource: "api:batch".to_string(),
                endpoint: "/api/now/batch".to_string(),
                status_code: 403,
                accessible: false,
                note: "Unavailable (sncfr will fall back to sequential GET requests)".to_string(),
            });

            for (res_id, endpoint, fallback_note) in PROBED_RESOURCES {
                let (status_code, accessible, note) =
                    match client.get_json::<Value>(endpoint, &[]).await {
                        Ok(_) => (200, true, "OK".to_string()),
                        Err(SncfrError::AclForbidden { .. }) => {
                            (403, false, (*fallback_note).to_string())
                        }
                        Err(SncfrError::NotFound { .. }) => (404, false, "Not Found".to_string()),
                        Err(SncfrError::NetworkOrInstance { status, .. }) => {
                            let code = status.unwrap_or(500);
                            (code, false, format!("HTTP {code}"))
                        }
                        Err(_) => (500, false, "Error".to_string()),
                    };
                capabilities.push(CapabilityCheck {
                    resource: (*res_id).to_string(),
                    endpoint: (*endpoint).to_string(),
                    status_code,
                    accessible,
                    note,
                });
            }
        }
    }

    let task_accessible = capabilities
        .iter()
        .find(|c| c.resource == "table:task")
        .is_some_and(|c| c.accessible);

    Ok(DoctorReport {
        healthy: task_accessible,
        profile: profile.name.clone(),
        instance_url: profile
            .instance_url
            .as_str()
            .trim_end_matches('/')
            .to_string(),
        auth_method: profile.auth_method.as_str().to_string(),
        read_only_locked: profile.is_read_only_locked(),
        read_only_reason: profile.read_only_lock_reason.clone(),
        identity,
        capabilities,
    })
}

/// Formats [`DoctorReport`] according to the resolved output mode.
pub fn format_doctor_report(report: &DoctorReport, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(report).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(report).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = String::new();
            out.push_str(&format!("# `sncfr doctor` — {}\n\n", report.instance_url));
            out.push_str(&format!(
                "- **Status**: {}\n",
                if report.healthy {
                    "HEALTHY"
                } else {
                    "DEGRADED"
                }
            ));
            out.push_str(&format!(
                "- **Profile**: `{}` (`{}`)\n",
                report.profile, report.auth_method
            ));
            out.push_str(&format!(
                "- **Safety Mode**: {}\n",
                if report.read_only_locked {
                    format!(
                        "Hard Read-Only Locked ({})",
                        report.read_only_reason.as_deref().unwrap_or("locked")
                    )
                } else {
                    "Read-Only by default (`--write` enabled)".to_string()
                }
            ));
            out.push_str(&format!(
                "- **User (`@me`)**: {} (`{}`, `sys_id={}`)\n",
                report.identity.display_name, report.identity.user_name, report.identity.sys_id
            ));
            let group_names: Vec<&str> = report
                .identity
                .groups
                .iter()
                .map(|g| g.name.as_str())
                .collect();
            out.push_str(&format!(
                "- **Groups (`@my-groups`)**: {}\n\n",
                if group_names.is_empty() {
                    "(none or dynamic fallback)".to_string()
                } else {
                    group_names.join(", ")
                }
            ));
            out.push_str("## ACL & Endpoint Capability Matrix\n\n");
            out.push_str("| Resource | Status | Accessible | Notes |\n");
            out.push_str("| :--- | :--- | :--- | :--- |\n");
            for cap in &report.capabilities {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | {} |\n",
                    cap.resource, cap.status_code, cap.accessible, cap.note
                ));
            }
            out
        }
        ResolvedOutputFormat::TerminalDossier | ResolvedOutputFormat::Table => {
            let mut out = String::new();
            out.push_str(&format!(
                "sncfr doctor — {} (profile: {}, auth: {})\n",
                report.instance_url, report.profile, report.auth_method
            ));
            out.push_str(&format!(
                "User (@me):      {} ({}) [sys_id: {}]\n",
                report.identity.display_name, report.identity.user_name, report.identity.sys_id
            ));
            let group_names: Vec<&str> = report
                .identity
                .groups
                .iter()
                .map(|g| g.name.as_str())
                .collect();
            out.push_str(&format!(
                "Groups:          {}\n",
                if group_names.is_empty() {
                    "(none or dynamic fallback)".to_string()
                } else {
                    group_names.join(", ")
                }
            ));
            out.push_str(&format!(
                "Safety Gate:     {}\n\n",
                if report.read_only_locked {
                    format!(
                        "HARD READ-ONLY LOCKED ({})",
                        report.read_only_reason.as_deref().unwrap_or("locked")
                    )
                } else {
                    "Read-Only by default (Dry-Run unless --write is passed)".to_string()
                }
            ));

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["RESOURCE", "HTTP", "ACCESS", "NOTES"]);
            for cap in &report.capabilities {
                table.add_row(vec![
                    cap.resource.as_str(),
                    &cap.status_code.to_string(),
                    if cap.accessible {
                        "ALLOW"
                    } else {
                        "RESTRICTED"
                    },
                    cap.note.as_str(),
                ]);
            }
            out.push_str(&table.to_string());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use crate::config::{AppConfig, AuthMethod, ProfileConfig};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use clap::Parser;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn doctor_resolves_identity_and_batches_capability_probes_with_graceful_403() {
        let server = MockServer::start().await;

        // 1. Mock `sys_user` for `@me`
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "u_sys_1", "display_value": "u_sys_1" },
                    "user_name": { "value": "eric.sabe", "display_value": "eric.sabe" },
                    "name": { "value": "Eric Sabe", "display_value": "Eric Sabe" },
                    "email": { "value": "eric@example.com", "display_value": "eric@example.com" }
                }]
            })))
            .mount(&server)
            .await;

        // 2. Mock `sys_user_grmember` for `@my-groups`
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_user_grmember"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "group": { "value": "g_sys_1", "display_value": "Cloud Platform" }
                }]
            })))
            .mount(&server)
            .await;

        // 3. Mock `/api/now/batch` with mixed 200 and 403 (`sys_journal_field` restricted)
        let ok_body = BASE64_STANDARD.encode(r#"{"result":[{"sys_id":"1"}]}"#);
        let forbidden_body = BASE64_STANDARD.encode(r#"{"error":{"message":"Access Denied"}}"#);
        let serviced: Vec<Value> = PROBED_RESOURCES
            .iter()
            .map(|(res_id, _, _)| {
                if *res_id == "table:sys_journal_field" {
                    json!({
                        "id": res_id,
                        "status_code": 403,
                        "status_text": "Forbidden",
                        "body": forbidden_body
                    })
                } else {
                    json!({
                        "id": res_id,
                        "status_code": 200,
                        "status_text": "OK",
                        "body": ok_body
                    })
                }
            })
            .collect();

        Mock::given(method("POST"))
            .and(path("/api/now/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "batch_request_id": "sncfr-doctor",
                "serviced_requests": serviced,
                "unserviced_requests": []
            })))
            .mount(&server)
            .await;

        let mut cfg = AppConfig {
            default_profile: Some("test".to_string()),
            profiles: BTreeMap::new(),
        };
        cfg.profiles.insert(
            "test".to_string(),
            ProfileConfig {
                instance: server.uri(),
                auth_method: AuthMethod::ApiKey,
                username: None,
                read_only: false,
                views: BTreeMap::new(),
            },
        );
        let cli = crate::cli::Cli::try_parse_from(["sncfr", "doctor"]).expect("parse doctor");
        let profile = cfg.resolve_profile(&cli).expect("resolve profile");
        let client = ReadOnlyClient::new(
            profile.instance_url.clone(),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "test-key".to_string(),
            },
        )
        .expect("client");

        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());

        let report = execute_doctor(&profile, &client, &cache)
            .await
            .expect("execute doctor");
        assert!(report.healthy);
        assert_eq!(report.identity.user_name, "eric.sabe");
        assert_eq!(report.identity.groups.len(), 1);
        assert_eq!(report.identity.groups[0].name, "Cloud Platform");

        let journal_cap = report
            .capabilities
            .iter()
            .find(|c| c.resource == "table:sys_journal_field")
            .expect("journal check");
        assert_eq!(journal_cap.status_code, 403);
        assert!(!journal_cap.accessible);
        assert!(journal_cap.note.contains("inline comments_and_work_notes"));

        let md = format_doctor_report(&report, ResolvedOutputFormat::Md);
        assert!(md.contains("Eric Sabe"));
        assert!(md.contains("table:sys_journal_field"));
    }
}
