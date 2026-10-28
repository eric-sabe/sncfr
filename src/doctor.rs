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
    /// Merged Instance Pack identity and active workarounds (PACK-6, PACK-7).
    pub pack: crate::pack::PackSummary,
    /// The capability record after this run's probes (CAP-6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_record: Vec<crate::capabilities::CapStatus>,
    /// Whether the merged pack lists this instance (NA-14).
    #[serde(default = "default_true")]
    pub pack_binds_instance: bool,
    /// User-pack choice entries that readable instance metadata contradicts (missing value or
    /// different label).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pack_drift: Vec<String>,
}

const fn default_true() -> bool {
    true
}

/// What sncfr does instead when a well-known probe table is forbidden.
fn probe_fallback_note(table: &str) -> &'static str {
    match table {
        "task" => "Base task table (required for cross-table search & prefix fallback)",
        "incident" => "Incident records (INC*)",
        "sc_req_item" => "Requested Item records (RITM*)",
        "change_request" => "Change Request records (CHG*)",
        "sys_journal_field" => {
            "403 Forbidden (sncfr will fall back to inline comments_and_work_notes)"
        }
        "sys_number" => "403 Forbidden (sncfr will use built-in ITIL prefixes + task fallback)",
        "sys_choice" => "403 Forbidden (choice label resolution will pass raw values)",
        "sys_dictionary" => "403 Forbidden (schema introspection will infer fields from records)",
        _ => "403 Forbidden",
    }
}

/// `(resource id, endpoint, 403 note)` for every probe: the pack's `core.probe_tables` (ADR-0004)
/// plus the Aggregate API.
#[cfg(test)]
fn probed_resources() -> Vec<(String, String, String)> {
    probed_resources_for(crate::pack::active())
}

fn probed_resources_for(pack: &crate::pack::MergedPack) -> Vec<(String, String, String)> {
    let mut probes: Vec<(String, String, String)> = pack
        .core
        .probe_tables
        .iter()
        .map(|t| {
            (
                format!("table:{t}"),
                format!("/api/now/table/{t}?sysparm_limit=1&sysparm_fields=sys_id"),
                probe_fallback_note(t).to_string(),
            )
        })
        .collect();
    probes.push((
        "api:stats".to_string(),
        "/api/now/stats/task?sysparm_count=true".to_string(),
        "Aggregate API (`sncfr stats`)".to_string(),
    ));
    probes
}

/// Executes `sncfr doctor`: verifies live authentication, resolves `@me` identity, and probes
/// the user's non-admin ACL capability matrix across core ServiceNow tables and REST APIs.
pub async fn execute_doctor(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
) -> Result<DoctorReport, SncfrError> {
    execute_doctor_with(profile, client, cache, crate::pack::active(), false).await
}

/// `sncfr doctor [--refresh]` against `pack`. `refresh` forgets the capability record first and
/// also probes the catalog API.
pub async fn execute_doctor_with(
    profile: &ResolvedProfile,
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    pack: &crate::pack::MergedPack,
    refresh: bool,
) -> Result<DoctorReport, SncfrError> {
    use crate::capabilities::{CapHint, CapSource, CapState, Capability, CapabilityRecord};
    if refresh {
        CapabilityRecord::clear(cache);
    }
    let identity = resolve_current_identity(client, cache, true).await?;

    let probes = probed_resources_for(pack);
    let sub_requests: Vec<BatchGetSubRequest> = probes
        .iter()
        .map(|(res, url, _)| BatchGetSubRequest::new(res, url))
        .collect();

    let mut capabilities = Vec::with_capacity(probes.len() + 1);

    match client.batch_get("sncfr-doctor", &sub_requests).await {
        Ok(batch_resp) => {
            capabilities.push(CapabilityCheck {
                resource: "api:batch".to_string(),
                endpoint: "/api/now/batch".to_string(),
                status_code: 200,
                accessible: true,
                note: "Single-roundtrip Ticket Dossier enabled".to_string(),
            });

            for (res_id, endpoint, fallback_note) in &probes {
                if let Some(sub) = batch_resp.get(res_id) {
                    let accessible = sub.is_success();
                    let note = if accessible {
                        "OK".to_string()
                    } else if sub.status_code == 403 {
                        fallback_note.clone()
                    } else {
                        format!("HTTP {}", sub.status_code)
                    };
                    capabilities.push(CapabilityCheck {
                        resource: res_id.clone(),
                        endpoint: endpoint.clone(),
                        status_code: sub.status_code,
                        accessible,
                        note,
                    });
                }
            }
        }
        Err(batch_err) => {
            let batch_code = match &batch_err {
                SncfrError::AclForbidden { .. } => 403,
                SncfrError::NotFound { .. } => 404,
                SncfrError::NetworkOrInstance {
                    status: Some(code), ..
                } => *code,
                _ => 403,
            };
            capabilities.push(CapabilityCheck {
                resource: "api:batch".to_string(),
                endpoint: "/api/now/batch".to_string(),
                status_code: batch_code,
                accessible: false,
                note: "Unavailable (sncfr will fall back to concurrent GET requests)".to_string(),
            });

            for (res_id, endpoint, fallback_note) in &probes {
                let (status_code, accessible, note) =
                    match client.get_json::<Value>(endpoint, &[]).await {
                        Ok(_) => (200, true, "OK".to_string()),
                        Err(SncfrError::AclForbidden { .. }) => (403, false, fallback_note.clone()),
                        Err(SncfrError::NotFound { .. }) => (404, false, "Not Found".to_string()),
                        Err(SncfrError::NetworkOrInstance { status, .. }) => {
                            let code = status.unwrap_or(500);
                            (code, false, format!("HTTP {code}"))
                        }
                        Err(_) => (500, false, "Error".to_string()),
                    };
                capabilities.push(CapabilityCheck {
                    resource: res_id.clone(),
                    endpoint: endpoint.clone(),
                    status_code,
                    accessible,
                    note,
                });
            }
        }
    }

    // CAP-5: tables the pack says may be missing are "not installed", not problems.
    for c in &mut capabilities {
        if let Some(table) = c.resource.strip_prefix("table:")
            && pack.doctor_absent_tables_ok.iter().any(|t| t == table)
            && matches!(c.status_code, 400 | 404)
        {
            c.note = "not installed".to_string();
        }
    }

    // Probes are observations (CAP-6).
    let probe_state = |code: u16| match code {
        200..=299 => (CapState::Available, None),
        403 => (CapState::Unauthorized, Some(CapHint::Acl)),
        400 => (CapState::Unavailable, Some(CapHint::InvalidTable)),
        _ => (CapState::Unavailable, None),
    };
    for (resource, cap) in [
        ("api:batch", Capability::BatchApi),
        ("table:sys_number", Capability::NumberTableReadable),
        ("table:sys_choice", Capability::ChoiceTableFilter),
        ("table:sys_dictionary", Capability::DictionaryReadable),
        ("api:stats", Capability::StatsGroupBy),
    ] {
        if let Some(c) = capabilities.iter().find(|c| c.resource == resource) {
            let (state, hint) = probe_state(c.status_code);
            CapabilityRecord::observe(
                cache,
                cap,
                state,
                CapSource::Probe,
                Some(c.status_code),
                hint,
            );
        }
    }
    if refresh {
        match client
            .get_json::<Value>("/api/sn_sc/servicecatalog/items", &[("sysparm_limit", "1")])
            .await
        {
            Ok(_) => CapabilityRecord::observe(
                cache,
                Capability::CatalogApi,
                CapState::Available,
                CapSource::Probe,
                Some(200),
                None,
            ),
            // ApiFamilyUnauthorized is recorded by the client itself.
            Err(SncfrError::ApiFamilyUnauthorized { .. }) => {}
            Err(SncfrError::NotFound { .. }) => CapabilityRecord::observe(
                cache,
                Capability::CatalogApi,
                CapState::Unavailable,
                CapSource::Probe,
                Some(404),
                None,
            ),
            Err(SncfrError::AclForbidden { .. }) => CapabilityRecord::observe(
                cache,
                Capability::CatalogApi,
                CapState::Unauthorized,
                CapSource::Probe,
                Some(403),
                Some(CapHint::Acl),
            ),
            Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => {
                return Err(e);
            }
            Err(_) => {}
        }
    }
    let capability_record = CapabilityRecord::load(cache).statuses(pack);

    // Pack drift: authoritative user choice sets vs readable instance metadata.
    let mut pack_drift = Vec::new();
    for (key, set) in &pack.choices {
        if set.origin == crate::pack::PackOrigin::Ootb || set.value.confirm_required {
            continue;
        }
        let Some((table, field)) = key.split_once('.') else {
            continue;
        };
        let Ok(schema) =
            crate::schema::load_or_sync_table_schema(client, cache, table, false).await
        else {
            continue;
        };
        let Some(instance) = schema.choices.get(field).filter(|c| !c.is_empty()) else {
            continue;
        };
        for entry in &set.value.values {
            match instance.iter().find(|c| c.value == entry.value) {
                None => pack_drift.push(format!(
                    "{key}: value {} (\"{}\") is not on the instance",
                    entry.value, entry.label
                )),
                Some(c) if c.label != entry.label => pack_drift.push(format!(
                    "{key}: value {} is \"{}\" in the pack but \"{}\" on the instance{}",
                    entry.value,
                    entry.label,
                    c.label,
                    if set.value.workaround {
                        " (workaround)"
                    } else {
                        ""
                    }
                )),
                Some(_) => {}
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
        pack: pack.summary(),
        capability_record,
        pack_binds_instance: pack.binds(&profile.instance_key),
        pack_drift,
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
            out.push_str(&format!(
                "- **Instance Pack**: {}\n",
                report.pack.headline()
            ));
            if !report.pack_binds_instance {
                out.push_str("  - ⚠ this pack does not list this instance in `instances`: writes are refused\n");
            }
            for w in &report.pack.workarounds {
                out.push_str(&format!("  - workaround: {w}\n"));
            }
            for d in &report.pack_drift {
                out.push_str(&format!("  - drift: {}\n", crate::untrusted::inline(d)));
            }
            out.push('\n');
            if !report.capability_record.is_empty() {
                out.push_str("## Capability Record\n\n| Capability | State | Source | Age |\n| :--- | :--- | :--- | :--- |\n");
                for c in &report.capability_record {
                    out.push_str(&format!(
                        "| `{}` | {} | {} | {} |\n",
                        c.capability,
                        c.state.as_str(),
                        c.source,
                        c.age_secs.map_or("—".to_string(), |a| format!("{a}s"))
                    ));
                }
                out.push('\n');
            }
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
            out.push_str(&format!("Instance Pack:   {}\n", report.pack.headline()));
            if !report.pack_binds_instance {
                out.push_str("  ⚠ pack does not list this instance: writes are refused\n");
            }
            for w in &report.pack.workarounds {
                out.push_str(&format!("  workaround:    {w}\n"));
            }
            for d in &report.pack_drift {
                out.push_str(&format!(
                    "  drift:         {}\n",
                    crate::untrusted::clean(d)
                ));
            }
            let caps: Vec<String> = report
                .capability_record
                .iter()
                .map(|c| format!("{}={}", c.capability, c.state.as_str()))
                .collect();
            if !caps.is_empty() {
                out.push_str(&format!("Capabilities:    {}\n", caps.join(", ")));
            }
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
        let serviced: Vec<Value> = probed_resources()
            .iter()
            .map(|(res_id, _, _)| {
                if res_id == "table:sys_journal_field" {
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
                ..Default::default()
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
