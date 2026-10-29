//! `sncfr cmdb lookup <host|ip|fqdn|serial|sys_id>` (WF-1): read-only CI lookup with support
//! group, relationships, and open tasks. Only `&ReadOnlyClient` is used (NA-1).

use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Identity fields when the pack names none for the CI class.
const DEFAULT_CI_FIELDS: [&str; 10] = [
    "sys_id",
    "name",
    "sys_class_name",
    "fqdn",
    "ip_address",
    "serial_number",
    "support_group",
    "install_status",
    "operational_status",
    "sys_updated_on",
];
/// Rows per relationship direction and for open tasks.
const RELATED_LIMIT: &str = "20";
/// Matches listed before a lookup is reported ambiguous.
const MATCH_LIMIT: &str = "10";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiRelation {
    pub name: String,
    pub sys_id: String,
    #[serde(rename = "type")]
    pub rel_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiOpenTask {
    pub number: String,
    pub short_description: String,
    pub state: String,
    pub updated_on: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdbLookup {
    pub input: String,
    /// `sys_id`, `ip`, `fqdn`, or `name`.
    pub matched_by: String,
    pub ambiguous: bool,
    /// The one matching CI's fields (display values).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ci: BTreeMap<String, String>,
    /// Identity of every match when there is more than one (ask the user which).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<CiRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CiRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_tasks: Vec<CiOpenTask>,
    /// The open rule applied to `task_ci` (prefixed with `task.`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub open_rule: String,
}

/// How the input is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputShape {
    SysId,
    Ip,
    Fqdn,
    Name,
}

fn shape_of(input: &str) -> InputShape {
    if crate::untrusted::is_sys_id(input) {
        InputShape::SysId
    } else if input.parse::<std::net::IpAddr>().is_ok() {
        InputShape::Ip
    } else if input.contains('.') {
        InputShape::Fqdn
    } else {
        InputShape::Name
    }
}

/// `active=true^stateNOT IN6,7` → `task.active=true^task.stateNOT IN6,7` (each term, `^OR`
/// included). Clauses like `^NQ` are rejected by `pack validate`, so none reach here.
pub fn prefix_terms(query: &str, prefix: &str) -> String {
    query
        .split('^')
        .filter(|t| !t.is_empty())
        .map(|t| match t.strip_prefix("OR") {
            Some(rest) => format!("OR{prefix}{rest}"),
            None if t.starts_with("ORDERBY") => t.to_string(),
            None => format!("{prefix}{t}"),
        })
        .collect::<Vec<_>>()
        .join("^")
}

/// The open rule for tasks related to a CI (Q-2): the pack's `open_rule.task`, else
/// `active=true`, prefixed for `task_ci`.
fn task_open_rule(pack: &crate::pack::MergedPack) -> String {
    let rule = pack
        .open_rules
        .get("task")
        .map_or_else(|| "active=true".to_string(), |r| r.value.query.clone());
    prefix_terms(&rule, "task.")
}

fn row_fields(row: &Value, fields: &[String]) -> BTreeMap<String, String> {
    fields
        .iter()
        .filter_map(|f| {
            let v = extract_field_display(row, f)?;
            (!v.is_empty()).then(|| (f.clone(), v))
        })
        .collect()
}

async fn rows(
    client: &ReadOnlyClient,
    table: &str,
    query: &str,
    fields: &str,
    limit: &str,
) -> Result<Vec<Value>, SncfrError> {
    let resp: Value = client
        .get_json(
            &format!("/api/now/table/{table}"),
            &[
                ("sysparm_query", query),
                ("sysparm_fields", fields),
                ("sysparm_display_value", "all"),
                ("sysparm_limit", limit),
            ],
        )
        .await?;
    Ok(resp
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Executes `sncfr cmdb lookup <input>`.
pub async fn execute_cmdb_lookup(
    client: &ReadOnlyClient,
    input: &str,
) -> Result<CmdbLookup, SncfrError> {
    let input = input.trim();
    let value = crate::untrusted::query_value(input)?;
    let pack = crate::pack::active();
    let shape = shape_of(input);
    let identity: Vec<String> = DEFAULT_CI_FIELDS.iter().map(|f| (*f).to_string()).collect();
    let id_fields = identity.join(",");

    let found: Vec<Value> = match shape {
        InputShape::SysId => {
            let resp: Value = client
                .get_json(
                    &format!("/api/now/table/cmdb_ci/{input}"),
                    &[
                        ("sysparm_fields", id_fields.as_str()),
                        ("sysparm_display_value", "all"),
                    ],
                )
                .await?;
            resp.get("result").cloned().into_iter().collect()
        }
        InputShape::Ip => {
            let q = format!("ip_address={value}");
            let mut found = rows(client, "cmdb_ci_server", &q, &id_fields, MATCH_LIMIT).await?;
            if found.is_empty() {
                // A CI whose address lives on a NIC record.
                let nics =
                    rows(client, "cmdb_ci_ip_address", &q, "nic.cmdb_ci", MATCH_LIMIT).await?;
                let mut ids: Vec<String> = nics
                    .iter()
                    .filter_map(|n| extract_field_value(n, "nic.cmdb_ci"))
                    .filter(|id| crate::untrusted::is_sys_id(id))
                    .collect();
                ids.dedup();
                if !ids.is_empty() {
                    let q = format!("sys_idIN{}", ids.join(","));
                    found = rows(client, "cmdb_ci", &q, &id_fields, MATCH_LIMIT).await?;
                }
            }
            found
        }
        InputShape::Fqdn => {
            let q = format!("fqdn={value}^ORname={value}");
            rows(client, "cmdb_ci_server", &q, &id_fields, MATCH_LIMIT).await?
        }
        InputShape::Name => {
            let q = format!("name={value}^ORnameSTARTSWITH{value}.");
            let found = rows(client, "cmdb_ci_server", &q, &id_fields, MATCH_LIMIT).await?;
            if found.is_empty() {
                let q = format!("serial_number={value}");
                rows(client, "cmdb_ci_server", &q, &id_fields, MATCH_LIMIT).await?
            } else {
                found
            }
        }
    };
    let matched_by = match shape {
        InputShape::SysId => "sys_id",
        InputShape::Ip => "ip",
        InputShape::Fqdn => "fqdn",
        InputShape::Name => "name",
    }
    .to_string();

    let mut out = CmdbLookup {
        input: input.to_string(),
        matched_by,
        ..Default::default()
    };
    match found.as_slice() {
        [] => {
            return Err(SncfrError::NotFound {
                identifier: input.to_string(),
                table: Some("cmdb_ci".to_string()),
            });
        }
        [one] => {
            let sys_id = extract_field_value(one, "sys_id").unwrap_or_default();
            let class = extract_field_value(one, "sys_class_name").unwrap_or_default();
            // WF-1: fields from `fields.default.<ci class>` when the pack names them.
            let fields = pack
                .default_fields(&class, false)
                .filter(|_| crate::untrusted::is_table_name(&class))
                .unwrap_or_else(|| identity.clone());
            out.ci = if fields == identity {
                row_fields(one, &fields)
            } else {
                let resp: Value = client
                    .get_json(
                        &format!("/api/now/table/{class}/{sys_id}"),
                        &[
                            ("sysparm_fields", fields.join(",").as_str()),
                            ("sysparm_display_value", "all"),
                        ],
                    )
                    .await?;
                row_fields(resp.get("result").unwrap_or(&resp), &fields)
            };
            if crate::untrusted::is_sys_id(&sys_id) {
                out.open_rule = task_open_rule(pack);
                let parent_q = format!("child={sys_id}");
                let child_q = format!("parent={sys_id}");
                let task_q = format!("ci_item={sys_id}^{}", out.open_rule);
                let (parents, children, tasks) = tokio::join!(
                    rows(
                        client,
                        "cmdb_rel_ci",
                        &parent_q,
                        "parent,type",
                        RELATED_LIMIT
                    ),
                    rows(client, "cmdb_rel_ci", &child_q, "child,type", RELATED_LIMIT),
                    rows(
                        client,
                        "task_ci",
                        &task_q,
                        "task,task.number,task.short_description,task.state,task.sys_updated_on",
                        RELATED_LIMIT
                    ),
                );
                // Relationships and tasks degrade to empty under ACLs; the CI itself is the answer.
                out.parents = relations(&parents.unwrap_or_default(), "parent");
                out.children = relations(&children.unwrap_or_default(), "child");
                let mut tasks: Vec<CiOpenTask> = tasks
                    .unwrap_or_default()
                    .iter()
                    .map(|t| CiOpenTask {
                        number: extract_field_display(t, "task.number").unwrap_or_default(),
                        short_description: extract_field_display(t, "task.short_description")
                            .unwrap_or_default(),
                        state: extract_field_display(t, "task.state").unwrap_or_default(),
                        updated_on: extract_field_value(t, "task.sys_updated_on")
                            .unwrap_or_default(),
                    })
                    .collect();
                // PERF-5: sorted here, not with a dot-walked ORDERBY.
                tasks.sort_by(|a, b| b.updated_on.cmp(&a.updated_on));
                out.open_tasks = tasks;
            }
        }
        many => {
            out.ambiguous = true;
            out.matches = many.iter().map(|r| row_fields(r, &identity)).collect();
        }
    }
    Ok(out)
}

fn relations(rows: &[Value], side: &str) -> Vec<CiRelation> {
    rows.iter()
        .filter_map(|r| {
            Some(CiRelation {
                name: extract_field_display(r, side)?,
                sys_id: extract_field_value(r, side).unwrap_or_default(),
                rel_type: extract_field_display(r, "type").unwrap_or_default(),
            })
        })
        .collect()
}

pub fn format_cmdb_lookup(l: &CmdbLookup, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(l).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(l).unwrap_or_default(),
        _ => {
            let md = format == ResolvedOutputFormat::Md;
            let t = |s: &str| {
                if md {
                    crate::untrusted::inline(s)
                } else {
                    crate::untrusted::clean(s).replace('\n', " ⏎ ")
                }
            };
            let mut out = String::new();
            if l.ambiguous {
                let _ = writeln!(
                    out,
                    "{} CIs match \"{}\" ({}). Ask which one is meant, then look it up by sys_id:",
                    l.matches.len(),
                    t(&l.input),
                    l.matched_by
                );
                for m in &l.matches {
                    let _ = writeln!(
                        out,
                        "- {} [{}] sys_id {}",
                        t(m.get("name").map_or("", String::as_str)),
                        t(m.get("sys_class_name").map_or("", String::as_str)),
                        t(m.get("sys_id").map_or("", String::as_str)),
                    );
                }
                return out;
            }
            let name = l.ci.get("name").map_or(l.input.as_str(), String::as_str);
            let _ = writeln!(out, "{}{}", if md { "# " } else { "" }, t(name));
            for (k, v) in &l.ci {
                let _ = writeln!(out, "- {k}: {}", t(v));
            }
            for (label, rels) in [("Parents", &l.parents), ("Children", &l.children)] {
                if !rels.is_empty() {
                    let _ = writeln!(out, "\n{label}:");
                    for r in rels {
                        let _ = writeln!(out, "- {} ({})", t(&r.name), t(&r.rel_type));
                    }
                }
            }
            let _ = writeln!(out, "\nOpen tasks ({}):", l.open_tasks.len());
            for task in &l.open_tasks {
                let _ = writeln!(
                    out,
                    "- {} [{}] {}",
                    t(&task.number),
                    t(&task.state),
                    t(&task.short_description)
                );
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_are_classified_and_open_rules_prefixed() {
        assert_eq!(
            shape_of("0123456789abcdef0123456789abcdef"),
            InputShape::SysId
        );
        assert_eq!(shape_of("10.0.0.5"), InputShape::Ip);
        assert_eq!(shape_of("fe80::1"), InputShape::Ip);
        assert_eq!(shape_of("web-01.example.com"), InputShape::Fqdn);
        assert_eq!(shape_of("web-01"), InputShape::Name);
        assert_eq!(
            prefix_terms("active=true^stateNOT IN6,7^ORpriority=1", "task."),
            "task.active=true^task.stateNOT IN6,7^ORtask.priority=1"
        );
    }
}
