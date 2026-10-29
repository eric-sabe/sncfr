use crate::cache::{CachedPrefixes, InstanceCache};
use crate::client::{ReadOnlyClient, extract_field_value};
use crate::error::SncfrError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Ticket prefixes known from the merged Instance Pack (the bundled `ootb` pack plus any user
/// layers; `docs/SPEC.md` Section 7.2).
pub fn builtin_prefixes() -> BTreeMap<String, String> {
    crate::pack::active().prefix_map()
}

/// Splits a ticket number like `"inc0010042"` into `Some(("INC", "INC0010042"))`. One `-` between
/// the prefix and the digits is accepted (`"abc-1234567"` → `("ABC", "ABC-1234567")`); the number
/// keeps its separator when it is sent to `number=` (ID-2).
pub fn split_ticket_prefix(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    let first_digit_idx = trimmed.find(|c: char| c.is_ascii_digit())?;
    if first_digit_idx == 0 {
        return None;
    }
    let head = &trimmed[..first_digit_idx];
    let rest = &trimmed[first_digit_idx..];
    let prefix = head.strip_suffix('-').unwrap_or(head);
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    if !rest.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((prefix.to_ascii_uppercase(), trimmed.to_ascii_uppercase()))
}

/// Returns `true` if `s` looks like a 32-character hexadecimal ServiceNow `sys_id`.
pub fn is_sys_id(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolves a table name or prefix shorthand (`"inc"` -> `"incident"`, `"custom_table"` -> `"custom_table"`).
pub fn resolve_table_name(table_or_prefix: &str, prefixes: &CachedPrefixes) -> String {
    let trimmed = table_or_prefix.trim();
    let upper = trimmed.to_ascii_uppercase();
    if let Some(mapped) = prefixes.prefixes.get(&upper) {
        return mapped.clone();
    }
    if let Some(mapped) = builtin_prefixes().get(&upper) {
        return mapped.clone();
    }
    trimmed.to_ascii_lowercase()
}

/// The effective prefix map (ID-1): `ootb` defaults < `sys_number` < learned < user pack.
pub fn effective_prefixes(
    sys_number: &BTreeMap<String, String>,
    learned: &BTreeMap<String, String>,
    pack: &crate::pack::MergedPack,
) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = pack
        .prefixes
        .iter()
        .filter(|(_, v)| v.origin == crate::pack::PackOrigin::Ootb)
        .map(|(k, v)| (k.clone(), v.value.clone()))
        .collect();
    map.extend(sys_number.iter().map(|(k, v)| (k.clone(), v.clone())));
    map.extend(learned.iter().map(|(k, v)| (k.clone(), v.clone())));
    map.extend(
        pack.prefixes
            .iter()
            .filter(|(_, v)| v.origin != crate::pack::PackOrigin::Ootb)
            .map(|(k, v)| (k.clone(), v.value.clone())),
    );
    map
}

/// Reads `sys_number` (prefix -> table, instance metadata) and records `number_table_readable`.
/// `None` when it is unreadable (403 is common for non-admins).
pub async fn fetch_sys_number(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
) -> Result<Option<BTreeMap<String, String>>, SncfrError> {
    let mut sys_number = BTreeMap::new();
    let query = [
        ("sysparm_fields", "prefix,category"),
        ("sysparm_limit", "500"),
        ("sysparm_display_value", "false"),
    ];
    use crate::capabilities::{CapHint, CapSource, CapState, Capability, CapabilityRecord};
    let result = client
        .get_json::<Value>("/api/now/table/sys_number", &query)
        .await;
    match result {
        Ok(resp) => {
            CapabilityRecord::observe(
                cache,
                Capability::NumberTableReadable,
                CapState::Available,
                CapSource::Observed,
                Some(200),
                None,
            );
            if let Some(rows) = resp.get("result").and_then(Value::as_array) {
                for row in rows {
                    if let (Some(prefix), Some(category)) = (
                        extract_field_value(row, "prefix"),
                        extract_field_value(row, "category"),
                    ) {
                        let p = prefix.trim().to_ascii_uppercase();
                        let c = category.trim().to_ascii_lowercase();
                        if !p.is_empty() && !c.is_empty() {
                            sys_number.insert(p, c);
                        }
                    }
                }
            }
            Ok(Some(sys_number))
        }
        Err(e @ (SncfrError::AuthExpired { .. } | SncfrError::AuthRequired { .. })) => Err(e),
        Err(SncfrError::AclForbidden { .. }) => {
            // Common for non-admins: the pack's prefixes and the task fallback still work.
            CapabilityRecord::observe(
                cache,
                Capability::NumberTableReadable,
                CapState::Unauthorized,
                CapSource::Observed,
                Some(403),
                Some(CapHint::Acl),
            );
            Ok(None)
        }
        Err(_) => Ok(None),
    }
}

/// Loads [`CachedPrefixes`] from `prefixes.json` if fresh, or syncs from `sys_number` (falling back
/// to the pack's prefixes on `403 Forbidden`). Returns the effective map; learned prefixes survive
/// a resync.
pub async fn load_or_sync_prefixes(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    force_sync: bool,
) -> Result<CachedPrefixes, SncfrError> {
    let pack = crate::pack::active();
    if !force_sync && let Ok(Some(cached)) = cache.read_prefixes() {
        return Ok(CachedPrefixes {
            prefixes: effective_prefixes(&cached.prefixes, &cached.learned, pack),
            learned: cached.learned,
        });
    }
    let learned = cache
        .read_allow_stale::<CachedPrefixes>(std::path::Path::new("prefixes.json"))
        .ok()
        .flatten()
        .map(|(p, _)| p.learned)
        .unwrap_or_default();

    let sys_number = fetch_sys_number(client, cache).await?.unwrap_or_default();

    // On disk: what sys_number returned plus learned prefixes (kept separately so a resync
    // keeps them).
    let mut on_disk = sys_number;
    on_disk.extend(learned.iter().map(|(k, v)| (k.clone(), v.clone())));
    let stored = CachedPrefixes {
        prefixes: on_disk,
        learned,
    };
    let _ = cache.write_prefixes(&stored);
    Ok(CachedPrefixes {
        prefixes: effective_prefixes(&stored.prefixes, &stored.learned, pack),
        learned: stored.learned,
    })
}

/// Resolved ticket metadata and full concrete-table JSON record (`sysparm_display_value=all`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTicket {
    pub number: String,
    pub table: String,
    pub sys_id: String,
    pub record: Value,
}

/// Resolves a ticket identifier (e.g., `"INC0010042"`, `"ritm0049210"`, `"SEC0010099"`, or a 32-char `sys_id`)
/// to its concrete ServiceNow table, `sys_id`, and full record (`docs/SPEC.md` Section 5.1).
pub async fn resolve_ticket(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    identifier: &str,
) -> Result<ResolvedTicket, SncfrError> {
    let mut prefixes = load_or_sync_prefixes(client, cache, false).await?;
    let trimmed = identifier.trim();

    // Case 1: Ticket number with alphabetic prefix (e.g. `INC0010042`, `SEC0010099`)
    if let Some((prefix, canonical_number)) = split_ticket_prefix(trimmed) {
        if let Some(target_table) = prefixes.prefixes.get(&prefix).cloned()
            && let Some(resolved) =
                query_ticket_in_table(client, &target_table, &canonical_number).await?
        {
            return Ok(resolved);
        }

        // Fallback: query base `task` table to discover `sys_class_name` and `sys_id`
        if let Some(resolved) =
            query_ticket_via_task_fallback(client, "number", &canonical_number).await?
        {
            // Learn the newly discovered custom prefix -> concrete table mapping in cache!
            if resolved.table != "task" {
                prefixes
                    .learned
                    .insert(prefix.clone(), resolved.table.clone());
                // Store the sys_number part as-is plus the learned map (not the effective map).
                let mut stored = cache.read_prefixes().ok().flatten().unwrap_or_default();
                stored.learned.clone_from(&prefixes.learned);
                stored.prefixes.insert(prefix, resolved.table.clone());
                let _ = cache.write_prefixes(&stored);
            }
            return Ok(resolved);
        }

        return Err(SncfrError::NotFound {
            identifier: canonical_number,
            table: prefixes.prefixes.get(&prefix).cloned(),
        });
    }

    // Case 2: 32-character hex `sys_id`
    if is_sys_id(trimmed)
        && let Some(resolved) = query_ticket_via_task_fallback(client, "sys_id", trimmed).await?
    {
        return Ok(resolved);
    }

    Err(SncfrError::NotFound {
        identifier: trimmed.to_string(),
        table: None,
    })
}

async fn query_ticket_in_table(
    client: &ReadOnlyClient,
    table: &str,
    canonical_number: &str,
) -> Result<Option<ResolvedTicket>, SncfrError> {
    let path = format!("/api/now/table/{table}");
    let q = format!(
        "number={}",
        crate::untrusted::query_value(canonical_number)?
    );
    let query = [
        ("sysparm_query", q.as_str()),
        ("sysparm_limit", "1"),
        ("sysparm_display_value", "all"),
    ];

    match client.get_json::<Value>(&path, &query).await {
        Ok(resp) => {
            let Some(first) = resp
                .get("result")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .cloned()
            else {
                return Ok(None);
            };
            let Some(sys_id) = extract_field_value(&first, "sys_id") else {
                return Ok(None);
            };
            let number = extract_field_value(&first, "number")
                .unwrap_or_else(|| canonical_number.to_string());
            let actual_table = extract_field_value(&first, "sys_class_name")
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| table.to_string());

            // If we queried `task` directly and discovered a child table, promote to the child table record
            if table == "task" && actual_table != "task" {
                let child_path = format!("/api/now/table/{actual_table}/{sys_id}");
                if let Ok(child_resp) = client
                    .get_json::<Value>(&child_path, &[("sysparm_display_value", "all")])
                    .await
                    && let Some(child_rec) = child_resp.get("result").cloned()
                {
                    return Ok(Some(ResolvedTicket {
                        number,
                        table: actual_table,
                        sys_id,
                        record: child_rec,
                    }));
                }
            }

            Ok(Some(ResolvedTicket {
                number,
                table: actual_table,
                sys_id,
                record: first,
            }))
        }
        // ID-4: a forbidden table is not a missing ticket.
        Err(SncfrError::AclForbidden { details, .. }) => Err(SncfrError::AclForbidden {
            resource: table.to_string(),
            details,
        }),
        Err(SncfrError::NotFound { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

async fn query_ticket_via_task_fallback(
    client: &ReadOnlyClient,
    field: &str,
    val: &str,
) -> Result<Option<ResolvedTicket>, SncfrError> {
    let q = format!("{field}={val}");
    let query = [
        ("sysparm_query", q.as_str()),
        ("sysparm_limit", "1"),
        ("sysparm_display_value", "all"),
    ];

    let resp: Value = match client.get_json("/api/now/table/task", &query).await {
        Ok(r) => r,
        Err(SncfrError::AclForbidden { details, .. }) => {
            return Err(SncfrError::AclForbidden {
                resource: "task".to_string(),
                details,
            });
        }
        Err(SncfrError::NotFound { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };

    let Some(task_rec) = resp
        .get("result")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .cloned()
    else {
        return Ok(None);
    };

    let Some(sys_id) = extract_field_value(&task_rec, "sys_id") else {
        return Ok(None);
    };
    let number = extract_field_value(&task_rec, "number").unwrap_or_else(|| val.to_string());
    let child_table =
        extract_field_value(&task_rec, "sys_class_name").unwrap_or_else(|| "task".to_string());

    if child_table != "task" {
        let child_path = format!("/api/now/table/{child_table}/{sys_id}");
        if let Ok(child_resp) = client
            .get_json::<Value>(&child_path, &[("sysparm_display_value", "all")])
            .await
            && let Some(child_rec) = child_resp.get("result").cloned()
        {
            return Ok(Some(ResolvedTicket {
                number,
                table: child_table,
                sys_id,
                record: child_rec,
            }));
        }
    }

    Ok(Some(ResolvedTicket {
        number,
        table: child_table,
        sys_id,
        record: task_rec,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn splits_standard_and_custom_ticket_prefixes() {
        assert_eq!(
            split_ticket_prefix("inc0010042"),
            Some(("INC".to_string(), "INC0010042".to_string()))
        );
        assert_eq!(
            split_ticket_prefix("RITM0049210"),
            Some(("RITM".to_string(), "RITM0049210".to_string()))
        );
        assert_eq!(
            split_ticket_prefix("u_sec009911"),
            Some(("U_SEC".to_string(), "U_SEC009911".to_string()))
        );
        assert_eq!(split_ticket_prefix("12345"), None);
    }

    #[test]
    fn accepts_one_hyphen_between_prefix_and_digits() {
        // ID-2
        assert_eq!(
            split_ticket_prefix("abc-1234567"),
            Some(("ABC".to_string(), "ABC-1234567".to_string()))
        );
        assert_eq!(split_ticket_prefix("ABC--1234567"), None);
        assert_eq!(split_ticket_prefix("-1234567"), None);
        assert_eq!(split_ticket_prefix("A-B-1234567"), None);
    }

    #[tokio::test]
    async fn resolves_custom_prefix_via_task_fallback_when_sys_number_is_403() {
        let server = MockServer::start().await;

        // 1. `sys_number` returns 403 Forbidden (common for non-admin users)
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": { "message": "Access Denied" }
            })))
            .mount(&server)
            .await;

        // 2. Base `task` table resolves `SEC0010099` and reports `sys_class_name = u_security_incident`
        Mock::given(method("GET"))
            .and(path("/api/now/table/task"))
            .and(query_param("sysparm_query", "number=SEC0010099"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [{
                    "sys_id": { "value": "sec_sys_99", "display_value": "sec_sys_99" },
                    "number": { "value": "SEC0010099", "display_value": "SEC0010099" },
                    "sys_class_name": { "value": "u_security_incident", "display_value": "Security Incident" }
                }]
            })))
            .mount(&server)
            .await;

        // 3. Concrete child table `u_security_incident` returns the full record with custom fields
        Mock::given(method("GET"))
            .and(path("/api/now/table/u_security_incident/sec_sys_99"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": {
                    "sys_id": { "value": "sec_sys_99", "display_value": "sec_sys_99" },
                    "number": { "value": "SEC0010099", "display_value": "SEC0010099" },
                    "sys_class_name": { "value": "u_security_incident", "display_value": "Security Incident" },
                    "u_severity": { "value": "high", "display_value": "High Severity" }
                }
            })))
            .mount(&server)
            .await;

        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "key".to_string(),
            },
        )
        .expect("client");

        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());

        let resolved = resolve_ticket(&client, &cache, "sec0010099")
            .await
            .expect("resolve custom ticket");
        assert_eq!(resolved.number, "SEC0010099");
        assert_eq!(resolved.table, "u_security_incident");
        assert_eq!(resolved.sys_id, "sec_sys_99");
        assert_eq!(
            extract_field_value(&resolved.record, "u_severity").as_deref(),
            Some("high")
        );

        // Verify the learned custom prefix (`SEC` -> `u_security_incident`) was cached in `prefixes.json`
        let cached_prefixes = cache
            .read_prefixes()
            .expect("read prefixes")
            .expect("prefixes cached");
        assert_eq!(
            cached_prefixes.prefixes.get("SEC").map(String::as_str),
            Some("u_security_incident")
        );
    }

    #[test]
    fn effective_prefixes_layer_ootb_sys_number_learned_then_user_pack() {
        // ID-1
        let ootb = crate::pack::ootb_file();
        let user = crate::pack::parse_pack(
            "schema_version = 1\npack_version = \"1\"\nname = \"t\"\ninstances = [\"x\"]\n[prefixes]\nINC = \"u_incident_override\"\nABC = \"u_abc_request\"\n",
        )
        .expect("pack");
        let pack = crate::pack::MergedPack::from_layers(&[
            (crate::pack::PackOrigin::Ootb, &ootb, None),
            (crate::pack::PackOrigin::Profile, &user, None),
        ]);
        let sys_number: BTreeMap<String, String> = [
            ("INC".to_string(), "incident".to_string()),
            ("SEC".to_string(), "u_sec".to_string()),
        ]
        .into();
        let learned: BTreeMap<String, String> =
            [("SEC".to_string(), "u_security_incident".to_string())].into();
        let map = effective_prefixes(&sys_number, &learned, &pack);
        assert_eq!(map["INC"], "u_incident_override", "user pack wins");
        assert_eq!(
            map["SEC"], "u_security_incident",
            "learned beats sys_number"
        );
        assert_eq!(map["ABC"], "u_abc_request");
        assert_eq!(map["RITM"], "sc_req_item", "ootb fills the rest");
    }

    #[tokio::test]
    async fn learned_prefixes_survive_a_forced_resync() {
        // ID-3 (the old resync dropped them)
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "error": { "message": "denied" } })),
            )
            .mount(&server)
            .await;
        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        cache
            .write_prefixes(&CachedPrefixes {
                prefixes: BTreeMap::new(),
                learned: [("SEC".to_string(), "u_security_incident".to_string())].into(),
            })
            .expect("seed");
        let synced = load_or_sync_prefixes(&client, &cache, true)
            .await
            .expect("sync");
        assert_eq!(
            synced.prefixes.get("SEC").map(String::as_str),
            Some("u_security_incident")
        );
        assert_eq!(
            synced.prefixes.get("INC").map(String::as_str),
            Some("incident")
        );
    }

    #[tokio::test]
    async fn a_forbidden_table_for_a_known_prefix_is_exit_4_naming_it() {
        // CT-34 (ID-4)
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/incident"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "error": { "message": "denied" } })),
            )
            .mount(&server)
            .await;
        let client = ReadOnlyClient::new(
            Url::parse(&server.uri()).expect("url"),
            ClientAuth::ApiKey {
                header_name: "x-sn-apikey".to_string(),
                token: "k".to_string(),
            },
        )
        .expect("client");
        let dir = tempdir().expect("tempdir");
        let cache = InstanceCache::with_instance_dir(dir.path().to_path_buf());
        let err = resolve_ticket(&client, &cache, "INC0012345")
            .await
            .unwrap_err();
        assert_eq!(err.code().exit_code(), 4, "{err}");
        assert!(err.to_string().contains("'incident'"), "{err}");
    }
}
