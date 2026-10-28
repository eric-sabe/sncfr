//! Instance Packs (ADR-0004): declarative per-instance facts layered over the bundled `ootb` pack.

pub mod merged;
pub mod schema;

use crate::error::SncfrError;
pub use merged::{MergedPack, PackOrigin, Sourced};
use schema::{PackFile, SUPPORTED_SCHEMA_VERSION};
use std::sync::OnceLock;

/// The bundled `ootb` pack: the single source of sncfr's built-in defaults (PACK-2).
pub const OOTB_PACK_TOML: &str = include_str!("ootb.pack.toml");

static ACTIVE: OnceLock<MergedPack> = OnceLock::new();

/// The parsed bundled pack. It is compiled in and covered by tests, so failing to parse it is a
/// build defect, not a runtime condition.
pub fn ootb_file() -> PackFile {
    parse_pack(OOTB_PACK_TOML).unwrap_or_else(|p| panic!("bundled ootb pack is invalid: {p:?}"))
}

/// The merged pack for this process. Installed once by `main` after loading the configured layers;
/// anything that runs before that (or in unit tests) sees the `ootb` pack alone.
pub fn active() -> &'static MergedPack {
    ACTIVE.get_or_init(|| MergedPack::from_layers(&[(PackOrigin::Ootb, &ootb_file(), None)]))
}

/// Installs the merged pack for this process. Returns `false` if one was already installed.
pub fn install(pack: MergedPack) -> bool {
    ACTIVE.set(pack).is_ok()
}

/// A single located problem in a pack file, rendered as `<source>:<line>:<col>: <message>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackProblem {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl PackProblem {
    pub fn render(&self, source: &str) -> String {
        format!("{source}:{}:{}: {}", self.line, self.col, self.message)
    }
}

/// Converts a byte offset in `text` to a 1-based `(line, col)`.
pub fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = &text[..offset];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, col)
}

/// Builds the `PACK_INVALID` error (exit 2) for `source` from its problems.
pub fn invalid(source: &str, problems: &[PackProblem]) -> SncfrError {
    SncfrError::PackInvalid {
        pack: source.to_string(),
        problems: problems.iter().map(|p| p.render(source)).collect(),
    }
}

/// Parses pack TOML, checking `schema_version` before the strict schema (PACK-4), so a pack
/// written for a newer major reports the version mismatch rather than its unknown keys.
pub fn parse_pack(text: &str) -> Result<PackFile, Vec<PackProblem>> {
    let to_problem = |err: toml::de::Error| {
        let (line, col) = err.span().map_or((1, 1), |s| line_col(text, s.start));
        PackProblem {
            line,
            col,
            message: err.message().trim().to_string(),
        }
    };
    let raw: toml::Table = toml::from_str(text).map_err(|e| vec![to_problem(e)])?;
    match raw.get("schema_version") {
        Some(toml::Value::Integer(v)) if *v == i64::from(SUPPORTED_SCHEMA_VERSION) => {}
        Some(toml::Value::Integer(v)) => {
            let offset = text.find("schema_version").unwrap_or(0);
            let (line, col) = line_col(text, offset);
            return Err(vec![PackProblem {
                line,
                col,
                message: format!(
                    "schema_version {v} is not supported; this sncfr understands schema_version {SUPPORTED_SCHEMA_VERSION}"
                ),
            }]);
        }
        _ => {
            return Err(vec![PackProblem {
                line: 1,
                col: 1,
                message: format!(
                    "missing integer `schema_version` (expected {SUPPORTED_SCHEMA_VERSION})"
                ),
            }]);
        }
    }
    toml::from_str::<PackFile>(text).map_err(|e| vec![to_problem(e)])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "schema_version = 1\npack_version = \"1\"\nname = \"t\"\n";

    #[test]
    fn parses_minimal_pack_with_active_default_status() {
        let pack = parse_pack(MINIMAL).expect("parse");
        assert_eq!(pack.name, "t");
        assert_eq!(pack.status, schema::PackStatus::Active);
        assert!(pack.prefixes.is_none());
    }

    #[test]
    fn rejects_unknown_schema_major_before_strict_parsing() {
        // CT-03: a v2 pack with keys this build doesn't know reports the version, not the keys.
        let text = "schema_version = 2\npack_version = \"1\"\nname = \"t\"\n[future]\nx = 1\n";
        let problems = parse_pack(text).unwrap_err();
        assert_eq!(problems.len(), 1);
        assert_eq!((problems[0].line, problems[0].col), (1, 1));
        assert!(
            problems[0]
                .message
                .contains("schema_version 2 is not supported")
        );
        assert!(problems[0].message.contains("schema_version 1"));
        let err = invalid("p.toml", &problems);
        assert_eq!(err.code().exit_code(), 2);
        assert_eq!(err.code().as_str(), "PACK_INVALID");
    }

    #[test]
    fn rejects_unknown_keys_and_read_only_at_any_depth() {
        // CT-04: unknown top-level key, and an attempt to set read_only inside [auth] (NA-4).
        for (text, key) in [
            (format!("{MINIMAL}bogus = true\n"), "bogus"),
            (format!("{MINIMAL}[auth]\nread_only = false\n"), "read_only"),
            (
                format!("{MINIMAL}[choices.incident.priority]\nvalues = []\ncolour = 1\n"),
                "colour",
            ),
        ] {
            let problems = parse_pack(&text).unwrap_err();
            assert!(
                problems[0].message.contains(key),
                "expected `{key}` in: {}",
                problems[0].message
            );
            assert!(
                problems[0].line > 1,
                "problem should be located: {problems:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_recipe_step_kind() {
        let text = format!(
            "{MINIMAL}[recipes.r]\nsteps = [{{ kind = \"update\", id = \"a\", table = \"incident\" }}]\n"
        );
        let problems = parse_pack(&text).unwrap_err();
        assert!(problems[0].message.contains("update"), "{problems:?}");
    }

    #[test]
    fn bundled_ootb_pack_parses_and_holds_the_former_constants() {
        let pack = active();
        assert_eq!(pack.name, "ootb");
        assert_eq!(pack.prefix_map().len(), 12);
        assert_eq!(pack.prefix_map()["RITM"], "sc_req_item");
        assert_eq!(pack.core.list_columns.len(), 8);
        assert_eq!(pack.core.dossier_core_fields.len(), 41);
        assert_eq!(
            pack.core.probe_tables.first().map(String::as_str),
            Some("task")
        );
        assert_eq!(pack.caller_field("incident"), "caller_id");
        assert_eq!(pack.caller_field("sc_request"), "requested_for");
        assert_eq!(pack.caller_field("change_request"), "opened_by");
        assert!(pack.choices["task.priority"].value.confirm_required);
    }

    #[test]
    fn table_shorthand_uses_prefixes_and_aliases() {
        let pack = active();
        assert_eq!(pack.resolve_table_shorthand("inc"), "incident");
        assert_eq!(pack.resolve_table_shorthand("RITM"), "sc_req_item");
        assert_eq!(
            pack.resolve_table_shorthand("case"),
            "sn_customerservice_case"
        );
        assert_eq!(pack.resolve_table_shorthand("u_custom"), "u_custom");
        assert_eq!(pack.resolve_table_shorthand("Incident"), "incident");
    }

    #[test]
    fn line_col_is_one_based() {
        assert_eq!(line_col("ab\ncd", 0), (1, 1));
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
    }
}
