//! User, group, and approval target resolution (SAFE-7, Q-4, APR-4; NA-3, NA-15).
//!
//! A reference never resolves by picking one of several matches: more than one candidate at any
//! step is `AMBIGUOUS_REFERENCE` (exit 2) with the candidates listed. Pack `suggest_map` entries
//! are shown as suggestions and never applied.

use crate::auth::resolve_current_identity;
use crate::cache::{CachedIdentity, InstanceCache};
use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::untrusted::{self, is_sys_id};
use serde_json::Value;

/// How a reference was resolved; shown in the preview's Source column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefResolution {
    Exact,
    MyGroups,
    Suffix(String),
    SysId,
    Me,
    Unassigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefMatch {
    pub sys_id: String,
    pub name: String,
    pub via: RefResolution,
    /// A pack `suggest_map` entry for the input (shown, never applied).
    pub suggestion: Option<String>,
}

impl RefMatch {
    /// `group:exact`, `group:suffix " - L2"`, `group:my_groups`, `user:exact`, `user:@me`, ...
    pub fn source_label(&self, kind: &str) -> String {
        match &self.via {
            RefResolution::Exact => format!("{kind}:exact"),
            RefResolution::MyGroups => format!("{kind}:my_groups"),
            RefResolution::Suffix(s) => format!("{kind}:suffix \"{s}\""),
            RefResolution::SysId => format!("{kind}:sys_id"),
            RefResolution::Me => format!("{kind}:@me"),
            RefResolution::Unassigned => format!("{kind}:none"),
        }
    }

    fn new(sys_id: String, name: String, via: RefResolution) -> Self {
        Self {
            sys_id,
            name,
            via,
            suggestion: None,
        }
    }
}

struct Row {
    sys_id: String,
    name: String,
}

fn rows(resp: &Value, name_field: &str) -> Vec<Row> {
    let mut out: Vec<Row> = Vec::new();
    for r in resp
        .get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(sys_id) = extract_field_value(r, "sys_id") else {
            continue;
        };
        if out.iter().any(|o| o.sys_id == sys_id) {
            continue;
        }
        let name = extract_field_display(r, name_field).unwrap_or_else(|| sys_id.clone());
        out.push(Row { sys_id, name });
    }
    out
}

fn mark_mine(name: &str, sys_id: &str, identity: Option<&CachedIdentity>) -> String {
    let mine = identity.is_some_and(|id| id.groups.iter().any(|g| g.sys_id == sys_id));
    let star = if mine { "  ★ you are a member" } else { "" };
    format!("{} ({}){star}", untrusted::inline(name), sys_id)
}

fn ambiguous(
    kind: &str,
    input: &str,
    detail: &str,
    candidates: Vec<String>,
    suggestion: Option<String>,
) -> SncfrError {
    SncfrError::AmbiguousReference {
        kind: kind.to_string(),
        input: untrusted::inline(input),
        detail: detail.to_string(),
        candidates,
        suggestion,
    }
}

/// Builds a query matching any of `names` exactly: `nameIN…`, or an `^OR` chain when a name
/// contains `,` (which `IN` would split).
fn name_any_of(field: &str, names: &[String]) -> Result<String, SncfrError> {
    for n in names {
        untrusted::query_value(n)?;
    }
    if names.iter().any(|n| untrusted::needs_or_chain(n)) {
        Ok(names
            .iter()
            .map(|n| format!("{field}={n}"))
            .collect::<Vec<_>>()
            .join("^OR"))
    } else {
        Ok(format!("{field}IN{}", names.join(",")))
    }
}

async fn query_groups(client: &ReadOnlyClient, query: &str) -> Result<Vec<Row>, SncfrError> {
    let resp: Value = client
        .get_json(
            "/api/now/table/sys_user_group",
            &[
                ("sysparm_query", query),
                ("sysparm_limit", "10"),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "sys_id,name"),
            ],
        )
        .await?;
    Ok(rows(&resp, "name"))
}

/// Resolves an assignment group (`--group`, `--assignment-group`, `--assign-to-group`):
/// `@my-groups` exact → `name=` exact → one query over the pack's `groups.suffixes` → error with
/// `nameSTARTSWITH` candidates. Any step with 2+ matches is ambiguous.
pub async fn resolve_group(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<RefMatch, SncfrError> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("unassigned")
    {
        return Ok(RefMatch::new(
            String::new(),
            "(unassigned)".to_string(),
            RefResolution::Unassigned,
        ));
    }
    if is_sys_id(trimmed) {
        return Ok(RefMatch::new(
            trimmed.to_string(),
            trimmed.to_string(),
            RefResolution::SysId,
        ));
    }
    let pack = crate::pack::active();
    let suggestion = pack.groups.suggest_map.get(trimmed).cloned();
    // Fetched (and cached) if needed: `@my-groups` is the first step and marks candidates.
    let identity = resolve_current_identity(client, cache, false).await.ok();

    if let Some(id) = &identity {
        let hits: Vec<_> = id
            .groups
            .iter()
            .filter(|g| g.name.eq_ignore_ascii_case(trimmed))
            .collect();
        match hits.as_slice() {
            [one] => {
                let mut m = RefMatch::new(
                    one.sys_id.clone(),
                    one.name.clone(),
                    RefResolution::MyGroups,
                );
                m.suggestion = suggestion;
                return Ok(m);
            }
            [] => {}
            many => {
                return Err(ambiguous(
                    "group",
                    trimmed,
                    "in your groups (names differ only in case)",
                    many.iter()
                        .map(|g| mark_mine(&g.name, &g.sys_id, Some(id)))
                        .collect(),
                    suggestion,
                ));
            }
        }
    }

    let exact = untrusted::query_value(trimmed)?;
    let found = query_groups(client, &format!("name={exact}")).await?;
    match found.as_slice() {
        [one] => {
            let mut m = RefMatch::new(one.sys_id.clone(), one.name.clone(), RefResolution::Exact);
            m.suggestion = suggestion;
            return Ok(m);
        }
        [] => {}
        many => {
            return Err(ambiguous(
                "group",
                trimmed,
                "with that exact name",
                many.iter()
                    .map(|r| mark_mine(&r.name, &r.sys_id, identity.as_ref()))
                    .collect(),
                suggestion,
            ));
        }
    }

    if !pack.groups.suffixes.is_empty() {
        let names: Vec<String> = pack
            .groups
            .suffixes
            .iter()
            .map(|s| format!("{trimmed}{s}"))
            .collect();
        let found = query_groups(client, &name_any_of("name", &names)?).await?;
        match found.as_slice() {
            [one] => {
                let suffix = pack
                    .groups
                    .suffixes
                    .iter()
                    .find(|s| one.name == format!("{trimmed}{s}"))
                    .cloned()
                    .unwrap_or_default();
                let mut m = RefMatch::new(
                    one.sys_id.clone(),
                    one.name.clone(),
                    RefResolution::Suffix(suffix),
                );
                m.suggestion = suggestion;
                return Ok(m);
            }
            [] => {}
            many => {
                let via = pack
                    .groups
                    .suffixes
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(ambiguous(
                    "group",
                    trimmed,
                    &format!("via suffixes {via}"),
                    many.iter()
                        .map(|r| mark_mine(&r.name, &r.sys_id, identity.as_ref()))
                        .collect(),
                    suggestion,
                ));
            }
        }
    }

    let similar = query_groups(client, &format!("nameSTARTSWITH{exact}"))
        .await
        .unwrap_or_default();
    Err(SncfrError::Validation {
        message: format!(
            "Could not resolve assignment group '{}'. Nothing was written.",
            untrusted::inline(trimmed)
        ),
        valid_choices: similar
            .iter()
            .map(|r| mark_mine(&r.name, &r.sys_id, identity.as_ref()))
            .collect(),
        remediation: Some(match &suggestion {
            Some(s) => format!(
                "Suggestion (not applied): {s}. Pass an exact group name or a group sys_id."
            ),
            None => {
                "Pass an exact ServiceNow group name or a 32-character group sys_id.".to_string()
            }
        }),
    })
}

/// Resolves a user (`--assign-to`, `--caller`, `--requested-for`): `@me`, a sys_id, or exactly one
/// `user_name`/`email`/`name` match.
pub async fn resolve_user(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    input: &str,
) -> Result<RefMatch, SncfrError> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("unassigned")
    {
        return Ok(RefMatch::new(
            String::new(),
            "(unassigned)".to_string(),
            RefResolution::Unassigned,
        ));
    }
    if trimmed.eq_ignore_ascii_case("@me") {
        let identity = resolve_current_identity(client, cache, false).await?;
        return Ok(RefMatch::new(
            identity.sys_id,
            identity.display_name,
            RefResolution::Me,
        ));
    }
    if is_sys_id(trimmed) {
        return Ok(RefMatch::new(
            trimmed.to_string(),
            trimmed.to_string(),
            RefResolution::SysId,
        ));
    }
    let v = untrusted::query_value(trimmed)?;
    let resp: Value = client
        .get_json(
            "/api/now/table/sys_user",
            &[
                (
                    "sysparm_query",
                    format!("user_name={v}^ORemail={v}^ORname={v}").as_str(),
                ),
                ("sysparm_limit", "10"),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "sys_id,name,user_name"),
            ],
        )
        .await?;
    let found = rows(&resp, "name");
    match found.as_slice() {
        [one] => Ok(RefMatch::new(one.sys_id.clone(), one.name.clone(), RefResolution::Exact)),
        [] => Err(SncfrError::Validation {
            message: format!("Could not resolve user reference '{}' in sys_user", untrusted::inline(trimmed)),
            valid_choices: vec![],
            remediation: Some(
                "Pass `@me`, `none`, a valid ServiceNow username/email, or a 32-character user `sys_id`.".to_string(),
            ),
        }),
        many => Err(ambiguous(
            "user",
            trimmed,
            "by user name, email, or name",
            many.iter().map(|r| format!("{} ({})", untrusted::inline(&r.name), r.sys_id)).collect(),
            None,
        )),
    }
}

/// Selects the single approval `approvals approve|reject` may act on (APR-4).
///
/// Only approvals in state `requested` that are assigned to the current user, directly or via
/// one of their assignment groups, are candidates. When the input is itself an approval sys_id,
/// only that record is considered. Never falls back to another approver's record or a
/// non-pending one: zero candidates is NOT_FOUND (exit 5) and several are ambiguous (exit 2).
pub fn select_approval_target(
    approval_or_ticket: &str,
    items: &[crate::workflows::ApprovalItem],
    identity: &CachedIdentity,
) -> Result<crate::workflows::ApprovalItem, SncfrError> {
    let input = approval_or_ticket.trim();
    let scoped: Vec<&crate::workflows::ApprovalItem> =
        match items.iter().find(|a| a.sys_id == input) {
            Some(direct) => vec![direct],
            None => items.iter().collect(),
        };
    let candidates: Vec<&crate::workflows::ApprovalItem> = scoped
        .iter()
        .copied()
        .filter(|a| a.is_requested() && a.is_linked_to(identity))
        .collect();

    match candidates.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err(SncfrError::NoActionableApproval {
            identifier: input.to_string(),
            found: scoped.iter().map(|a| a.describe()).collect(),
        }),
        many => Err(SncfrError::Validation {
            message: format!(
                "'{input}' has {} pending approvals assigned to you; choose one by its approval sys_id",
                many.len()
            ),
            valid_choices: many.iter().map(|a| a.describe()).collect(),
            remediation: Some(
                "Re-run with the approval sys_id, e.g. `sncfr approvals approve <approval_sys_id>`."
                    .to_string(),
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedGroup;
    use crate::client::ClientAuth;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::MockServer;

    #[test]
    fn name_lists_fall_back_to_or_chains_for_commas() {
        // CT-67 (unit half)
        assert_eq!(
            name_any_of("name", &["Net - L2".to_string(), "Net - L3".to_string()]).unwrap(),
            "nameINNet - L2,Net - L3"
        );
        assert_eq!(
            name_any_of("name", &["Ops, EMEA - L2".to_string(), "X".to_string()]).unwrap(),
            "name=Ops, EMEA - L2^ORname=X"
        );
        assert!(name_any_of("name", &["a^ORb".to_string()]).is_err());
    }

    #[tokio::test]
    async fn case_insensitive_duplicates_in_my_groups_are_ambiguous() {
        // CT-14b
        let server = MockServer::start().await;
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
            .write_identity(&CachedIdentity {
                sys_id: "u".to_string(),
                user_name: "pat.example".to_string(),
                display_name: "Pat Example".to_string(),
                email: None,
                groups: vec![
                    CachedGroup {
                        sys_id: "g1".to_string(),
                        name: "network".to_string(),
                    },
                    CachedGroup {
                        sys_id: "g2".to_string(),
                        name: "Network".to_string(),
                    },
                ],
            })
            .expect("identity");
        let err = resolve_group(&client, &cache, "NETWORK").await.unwrap_err();
        assert_eq!(err.code().as_str(), "AMBIGUOUS_REFERENCE");
        assert_eq!(err.code().exit_code(), 2);
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }
}
