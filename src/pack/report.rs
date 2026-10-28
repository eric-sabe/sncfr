//! `sncfr pack validate|show` (PACK-5, PACK-6).

use super::merged::{MergedPack, Sourced};
use super::{PackProblem, check_pack_file, invalid};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackValidation {
    pub path: String,
    pub valid: bool,
    pub warnings: Vec<String>,
}

/// Validates one pack file. Errors are returned as `PACK_INVALID` (exit 2), with any warnings
/// appended; a pack with only warnings is valid.
pub fn execute_pack_validate(path: &Path) -> Result<PackValidation, SncfrError> {
    let source = path.display().to_string();
    let (_, findings) = check_pack_file(path)?;
    let warnings: Vec<String> = findings
        .warnings
        .iter()
        .map(|w| format!("warning: {}", w.render(&source)))
        .collect();
    if !findings.errors.is_empty() {
        let mut err = invalid(&source, &findings.errors);
        if let SncfrError::PackInvalid { problems, .. } = &mut err {
            problems.extend(warnings);
        }
        return Err(err);
    }
    Ok(PackValidation {
        path: source,
        valid: true,
        warnings,
    })
}

pub fn format_pack_validation(v: &PackValidation, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(v).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(v).unwrap_or_default(),
        _ => {
            let mut out: Vec<String> = v.warnings.clone();
            out.push(format!(
                "{}: valid ({} warning{})",
                v.path,
                v.warnings.len(),
                if v.warnings.len() == 1 { "" } else { "s" }
            ));
            out.join("\n")
        }
    }
}

/// Renders the merged pack: a summary with per-entry origins, the full JSON/YAML, or `--toml`.
pub fn format_pack_show(
    pack: &MergedPack,
    toml: bool,
    format: ResolvedOutputFormat,
) -> Result<String, SncfrError> {
    if toml {
        return toml::to_string(&pack.to_pack_file()).map_err(|e| SncfrError::InvalidArgs {
            message: format!("Cannot render the merged pack as TOML: {e}"),
            remediation: None,
        });
    }
    Ok(match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(pack).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(pack).unwrap_or_default(),
        _ => summary_markdown(pack),
    })
}

fn rows<T>(
    out: &mut String,
    section: &str,
    map: &BTreeMap<String, Sourced<T>>,
    value: impl Fn(&T) -> String,
) {
    for (k, v) in map {
        out.push_str(&format!(
            "| {section} | `{k}` | {} | {} |\n",
            value(&v.value),
            v.origin.as_str()
        ));
    }
}

fn summary_markdown(pack: &MergedPack) -> String {
    let summary = pack.summary();
    let mut out = format!("## Instance Pack: {}\n\n", summary.headline());
    out.push_str(&format!("- **Layers**: {}\n", summary.layers.join(" → ")));
    out.push_str(&format!("- **Hash**: `{}`\n", pack.hash));
    let instances = pack.safety.instances.as_ref().map_or_else(
        || "(any; no user pack declares instances)".to_string(),
        |s| s.iter().cloned().collect::<Vec<_>>().join(", "),
    );
    out.push_str(&format!("- **Instances**: {instances}\n"));
    out.push_str(&format!(
        "- **Safety**: credential files {}; agent marker {}; rate limit {}\n",
        if pack.safety.allow_credentials_file {
            "allowed"
        } else {
            "forbidden"
        },
        pack.safety
            .agent_write_marker
            .as_deref()
            .map_or("none".to_string(), |m| format!("`{m}`")),
        pack.safety
            .max_requests_per_minute
            .map_or("none".to_string(), |r| format!("{r}/min")),
    ));
    if !summary.workarounds.is_empty() {
        out.push_str("- **Workarounds**:\n");
        for w in &summary.workarounds {
            out.push_str(&format!("  - {w}\n"));
        }
    }
    out.push_str("\n| Section | Key | Value | Origin |\n|---|---|---|---|\n");
    rows(&mut out, "prefixes", &pack.prefixes, |t| format!("`{t}`"));
    rows(&mut out, "choices", &pack.choices, |set| {
        let mut flags = Vec::new();
        if set.confirm_required {
            flags.push("confirm_required");
        }
        if set.workaround {
            flags.push("workaround");
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" ({})", flags.join(", "))
        };
        format!("{} values{flags}", set.values.len())
    });
    rows(&mut out, "open_rule", &pack.open_rules, |r| {
        format!("`{}`", r.query)
    });
    rows(&mut out, "closed_rule", &pack.closed_rules, |r| {
        format!("`{}`", r.query)
    });
    rows(&mut out, "fields.default", &pack.fields_default, |f| {
        format!(
            "list: {}; dossier: {}",
            f.list.join(", "),
            f.dossier.join(", ")
        )
    });
    rows(&mut out, "recipes", &pack.recipes, |r| {
        r.description.clone().unwrap_or_default()
    });
    if !pack.groups.suffixes.is_empty() {
        out.push_str(&format!(
            "| groups | `suffixes` | {} | — |\n",
            pack.groups
                .suffixes
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out
}

/// Problems rendered for the stderr envelope when a pack fails to load (used by tests).
pub fn render_problems(source: &str, problems: &[PackProblem]) -> Vec<String> {
    problems.iter().map(|p| p.render(source)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{active, parse_pack};

    #[test]
    fn validate_reports_warnings_and_errors_with_exit_codes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ok = dir.path().join("ok.toml");
        std::fs::write(
            &ok,
            "schema_version = 1\npack_version = \"1\"\nname = \"t\"\ninstances = [\"example.service-now.com\"]\n[choices.incident.priority]\nvalues = [{ value = \"5\", label = \"5 - Low\" }]\n",
        )
        .expect("write");
        let v = execute_pack_validate(&ok).expect("valid");
        assert!(v.valid);
        assert_eq!(v.warnings.len(), 1);
        assert!(
            format_pack_validation(&v, ResolvedOutputFormat::Md).ends_with("valid (1 warning)")
        );

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "schema_version = 1\npack_version = \"1\"\nname = \"t\"\n[groups]\nsuffixes = [\"work\"]\n").expect("write");
        let err = execute_pack_validate(&bad).unwrap_err();
        assert_eq!(err.code().exit_code(), 2);
        let msg = err.to_string();
        assert!(msg.contains("instances"), "{msg}");
        assert!(msg.contains("suffix `work`"), "{msg}");
    }

    #[test]
    fn show_renders_origins_and_reloadable_toml() {
        let md = format_pack_show(active(), false, ResolvedOutputFormat::Md).expect("md");
        assert!(md.contains("## Instance Pack: ootb"));
        assert!(md.contains("| prefixes | `INC` | `incident` | ootb |"));
        let toml_out = format_pack_show(active(), true, ResolvedOutputFormat::Md).expect("toml");
        let reparsed = parse_pack(&toml_out).expect("re-loadable");
        assert_eq!(reparsed.prefixes.expect("prefixes").len(), 12);
    }
}
