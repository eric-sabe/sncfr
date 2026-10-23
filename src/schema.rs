use crate::cache::{CachedChoice, CachedFieldMeta, CachedTableSchema, InstanceCache};
use crate::cli::SchemaArgs;
use crate::client::{ReadOnlyClient, extract_field_display, extract_field_value};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::resolve::{load_or_sync_prefixes, resolve_table_name};
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use serde_json::Value;
use std::collections::BTreeMap;

/// Loads [`CachedTableSchema`] from `schemas/<table>.json` if fresh, or syncs from
/// `sys_dictionary` and `sys_choice` (with graceful fallback to sample-record inference on `403`).
pub async fn load_or_sync_table_schema(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    table_or_prefix: &str,
    force_sync: bool,
) -> Result<CachedTableSchema, SncfrError> {
    let prefixes = load_or_sync_prefixes(client, cache, force_sync).await?;
    let table = resolve_table_name(table_or_prefix, &prefixes);

    if !force_sync && let Ok(Some(cached)) = cache.read_table_schema(&table) {
        return Ok(cached);
    }

    let tables_filter = if table == "task" {
        "name=task".to_string()
    } else {
        format!("nameIN{table},task")
    };

    let mut fields: BTreeMap<String, CachedFieldMeta> = BTreeMap::new();
    let mut child_field_overrides: BTreeMap<String, CachedFieldMeta> = BTreeMap::new();

    // 1. Query `sys_dictionary`
    let dict_query = format!("{tables_filter}^internal_type!=collection^active=true");
    match client
        .get_json::<Value>(
            "/api/now/table/sys_dictionary",
            &[
                ("sysparm_query", dict_query.as_str()),
                ("sysparm_display_value", "all"),
                (
                    "sysparm_fields",
                    "name,element,column_label,internal_type,mandatory,max_length,reference",
                ),
                ("sysparm_limit", "500"),
            ],
        )
        .await
    {
        Ok(resp) => {
            if let Some(rows) = resp.get("result").and_then(Value::as_array) {
                for row in rows {
                    let Some(element) = extract_field_value(row, "element") else {
                        continue;
                    };
                    let row_table =
                        extract_field_value(row, "name").unwrap_or_else(|| table.clone());
                    let label = extract_field_display(row, "column_label")
                        .unwrap_or_else(|| element.clone());
                    let internal_type = extract_field_value(row, "internal_type")
                        .unwrap_or_else(|| "string".to_string());
                    let mandatory = extract_field_value(row, "mandatory")
                        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
                    let max_length =
                        extract_field_value(row, "max_length").and_then(|s| s.parse::<u32>().ok());
                    let reference_table = extract_field_value(row, "reference");
                    let is_custom = element.starts_with("u_") || element.starts_with("x_");

                    let meta = CachedFieldMeta {
                        label,
                        internal_type,
                        mandatory,
                        max_length,
                        reference_table,
                        is_custom,
                    };

                    if row_table == table {
                        child_field_overrides.insert(element, meta);
                    } else {
                        fields.insert(element, meta);
                    }
                }
            }
        }
        Err(SncfrError::AuthExpired { instance }) => {
            return Err(SncfrError::AuthExpired { instance });
        }
        Err(SncfrError::AuthRequired { profile }) => {
            return Err(SncfrError::AuthRequired { profile });
        }
        Err(_) => {
            // Graceful fallback when `sys_dictionary` is 403 Forbidden: infer fields from 1 sample row
            let sample_path = format!("/api/now/table/{table}");
            if let Ok(sample_resp) = client
                .get_json::<Value>(
                    &sample_path,
                    &[("sysparm_limit", "1"), ("sysparm_display_value", "all")],
                )
                .await
                && let Some(first) = sample_resp
                    .get("result")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_object)
            {
                for k in first.keys() {
                    fields.insert(
                        k.clone(),
                        CachedFieldMeta {
                            label: k.clone(),
                            internal_type: "inferred".to_string(),
                            mandatory: false,
                            max_length: None,
                            reference_table: None,
                            is_custom: k.starts_with("u_") || k.starts_with("x_"),
                        },
                    );
                }
            }
        }
    }

    for (k, v) in child_field_overrides {
        fields.insert(k, v);
    }

    // 2. Query `sys_choice`
    let choice_query = format!("{tables_filter}^inactive=false^ORDERBYsequence");
    let mut base_choices: BTreeMap<String, Vec<CachedChoice>> = BTreeMap::new();
    let mut child_choices: BTreeMap<String, Vec<CachedChoice>> = BTreeMap::new();

    if let Ok(resp) = client
        .get_json::<Value>(
            "/api/now/table/sys_choice",
            &[
                ("sysparm_query", choice_query.as_str()),
                ("sysparm_display_value", "all"),
                ("sysparm_fields", "name,element,label,value,sequence"),
                ("sysparm_limit", "1000"),
            ],
        )
        .await
        && let Some(rows) = resp.get("result").and_then(Value::as_array)
    {
        for row in rows {
            let (Some(element), Some(label), Some(val)) = (
                extract_field_value(row, "element"),
                extract_field_display(row, "label"),
                extract_field_value(row, "value"),
            ) else {
                continue;
            };
            let row_table = extract_field_value(row, "name").unwrap_or_else(|| table.clone());
            let sequence = extract_field_value(row, "sequence").and_then(|s| s.parse::<i32>().ok());
            let choice = CachedChoice {
                label,
                value: val,
                sequence,
            };

            let target_map = if row_table == table {
                &mut child_choices
            } else {
                &mut base_choices
            };
            let list = target_map.entry(element).or_default();
            if !list.iter().any(|c| c.value == choice.value) {
                list.push(choice);
            }
        }
    }

    // Child table choice lists override base `task` choice lists for the same field
    let mut choices = base_choices;
    for (k, mut v) in child_choices {
        v.sort_by_key(|c| c.sequence.unwrap_or(i32::MAX));
        choices.insert(k, v);
    }

    let schema = CachedTableSchema {
        super_class: if table == "task" {
            None
        } else {
            Some("task".to_string())
        },
        table,
        fields,
        choices,
    };

    let _ = cache.write_table_schema(&schema);
    Ok(schema)
}

/// Validates and resolves a human choice label or raw value (e.g., `"In Progress"` -> `("In Progress", "2")`)
/// against [`CachedTableSchema`]. If the table has choices for `field` and `input` does not match any,
/// returns [`SncfrError::ValidationError`] with all valid options.
pub fn resolve_choice_value(
    schema: &CachedTableSchema,
    field: &str,
    input: &str,
) -> Result<(String, String), SncfrError> {
    let trimmed = input.trim();
    let Some(options) = schema.choices.get(field) else {
        return Ok((trimmed.to_string(), trimmed.to_string()));
    };
    if options.is_empty() {
        return Ok((trimmed.to_string(), trimmed.to_string()));
    }

    // Match by exact value or case-insensitive label/value
    if let Some(found) = options
        .iter()
        .find(|c| c.value.eq_ignore_ascii_case(trimmed) || c.label.eq_ignore_ascii_case(trimmed))
    {
        return Ok((found.label.clone(), found.value.clone()));
    }

    let valid_choices: Vec<String> = options
        .iter()
        .map(|c| format!("{} ({})", c.label, c.value))
        .collect();

    Err(SncfrError::Validation {
        message: format!(
            "Invalid choice value '{trimmed}' for field '{}.{}'",
            schema.table, field
        ),
        valid_choices,
        remediation: Some(format!(
            "Run `sncfr schema {} --choices {field}` to inspect all valid choice options.",
            schema.table
        )),
    })
}

/// Executes `sncfr schema <table|prefix> [--choices [field]] [--sync]`.
pub async fn execute_schema(
    client: &ReadOnlyClient,
    cache: &InstanceCache,
    args: &SchemaArgs,
) -> Result<CachedTableSchema, SncfrError> {
    load_or_sync_table_schema(client, cache, &args.table_or_prefix, args.sync).await
}

/// Formats [`CachedTableSchema`] according to `args` (`--choices`) and `format`.
pub fn format_schema(
    schema: &CachedTableSchema,
    args: &SchemaArgs,
    format: ResolvedOutputFormat,
) -> String {
    if let Some(choice_filter) = &args.choices {
        let filtered_choices: BTreeMap<&String, &Vec<CachedChoice>> = schema
            .choices
            .iter()
            .filter(|(k, _)| choice_filter == "*" || k.eq_ignore_ascii_case(choice_filter))
            .collect();

        match format {
            ResolvedOutputFormat::Json => {
                return serde_json::to_string_pretty(&filtered_choices).unwrap_or_default();
            }
            ResolvedOutputFormat::Yaml => {
                return serde_yaml::to_string(&filtered_choices).unwrap_or_default();
            }
            ResolvedOutputFormat::Md => {
                let mut out = format!("# Choices for `{}`\n\n", schema.table);
                for (field, list) in filtered_choices {
                    out.push_str(&format!("## `{field}`\n\n"));
                    for c in list {
                        out.push_str(&format!("- **{}**: `{}`\n", c.label, c.value));
                    }
                    out.push('\n');
                }
                return out;
            }
            ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL_CONDENSED)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec!["FIELD", "LABEL", "VALUE", "SEQUENCE"]);
                for (field, list) in filtered_choices {
                    for c in list {
                        table.add_row(vec![
                            field.as_str(),
                            c.label.as_str(),
                            c.value.as_str(),
                            &c.sequence.map(|s| s.to_string()).unwrap_or_default(),
                        ]);
                    }
                }
                return table.to_string();
            }
        }
    }

    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(schema).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(schema).unwrap_or_default(),
        ResolvedOutputFormat::Md => {
            let mut out = format!(
                "# Schema: `{}` ({} fields, {} choice lists)\n\n",
                schema.table,
                schema.fields.len(),
                schema.choices.len()
            );
            out.push_str("| Field | Label | Type | Mandatory | Custom (`u_`/`x_`) | Choices |\n");
            out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for (name, meta) in &schema.fields {
                let choice_count = schema.choices.get(name).map(Vec::len).unwrap_or(0);
                out.push_str(&format!(
                    "| `{}` | {} | `{}` | `{}` | `{}` | {} |\n",
                    name,
                    meta.label,
                    meta.internal_type,
                    meta.mandatory,
                    meta.is_custom,
                    choice_count
                ));
            }
            out
        }
        ResolvedOutputFormat::Table | ResolvedOutputFormat::TerminalDossier => {
            let mut table = Table::new();
            let width = table.width().unwrap_or(120).max(120);
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(width)
                .set_header(vec![
                    "FIELD",
                    "LABEL",
                    "TYPE",
                    "MANDATORY",
                    "CUSTOM",
                    "CHOICES",
                ]);
            for (name, meta) in &schema.fields {
                let choice_count = schema.choices.get(name).map(Vec::len).unwrap_or(0);
                table.add_row(vec![
                    name.as_str(),
                    meta.label.as_str(),
                    meta.internal_type.as_str(),
                    if meta.mandatory { "true" } else { "false" },
                    if meta.is_custom { "yes" } else { "" },
                    &choice_count.to_string(),
                ]);
            }
            format!(
                "{table}\n({} fields on '{}')",
                schema.fields.len(),
                schema.table
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientAuth;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn syncs_schema_and_validates_choices_with_child_table_override() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_dictionary"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [
                    {
                        "name": { "value": "incident", "display_value": "Incident" },
                        "element": { "value": "state", "display_value": "state" },
                        "column_label": { "value": "State", "display_value": "State" },
                        "internal_type": { "value": "integer", "display_value": "Integer" },
                        "mandatory": { "value": "false", "display_value": "false" }
                    },
                    {
                        "name": { "value": "incident", "display_value": "Incident" },
                        "element": { "value": "u_environment", "display_value": "u_environment" },
                        "column_label": { "value": "Environment", "display_value": "Environment" },
                        "internal_type": { "value": "string", "display_value": "String" },
                        "mandatory": { "value": "true", "display_value": "true" }
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_choice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": [
                    {
                        "name": { "value": "task", "display_value": "Task" },
                        "element": { "value": "state", "display_value": "state" },
                        "label": { "value": "Open", "display_value": "Open" },
                        "value": { "value": "1", "display_value": "1" },
                        "sequence": { "value": "1", "display_value": "1" }
                    },
                    {
                        "name": { "value": "incident", "display_value": "Incident" },
                        "element": { "value": "state", "display_value": "state" },
                        "label": { "value": "New", "display_value": "New" },
                        "value": { "value": "1", "display_value": "1" },
                        "sequence": { "value": "1", "display_value": "1" }
                    },
                    {
                        "name": { "value": "incident", "display_value": "Incident" },
                        "element": { "value": "state", "display_value": "state" },
                        "label": { "value": "In Progress", "display_value": "In Progress" },
                        "value": { "value": "2", "display_value": "2" },
                        "sequence": { "value": "2", "display_value": "2" }
                    }
                ]
            })))
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

        let schema = load_or_sync_table_schema(&client, &cache, "inc", false)
            .await
            .expect("sync schema");
        assert_eq!(schema.table, "incident");
        assert!(schema.fields["u_environment"].is_custom);

        // Verify child table (`incident`) choices overrode `task` choices for `state`
        let (disp, val) =
            resolve_choice_value(&schema, "state", "in progress").expect("resolve choice");
        assert_eq!(disp, "In Progress");
        assert_eq!(val, "2");

        // Invalid choice returns Validation (exit code 2) with valid_choices
        let err = resolve_choice_value(&schema, "state", "BogusState").unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        assert_eq!(
            err.to_envelope().error.valid_choices,
            vec!["New (1)".to_string(), "In Progress (2)".to_string()]
        );
    }
}
