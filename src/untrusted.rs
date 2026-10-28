//! Trust-boundary guards (NA-9, NA-13).
//!
//! - [`query_value`]: values interpolated into ServiceNow encoded queries can't add, remove, or
//!   reorder query terms.
//! - [`check_api_path`]: table names that reach a request path are plain identifiers.
//! - [`clean`] and friends: instance- or pack-sourced text shown to people or agents can't carry
//!   control/format characters, terminal escapes, or Markdown structure.

use crate::error::SncfrError;
use unicode_general_category::{GeneralCategory, get_general_category};

/// Why `value` is unsafe to interpolate into an encoded query, if it is.
fn query_value_problem(value: &str, in_list: bool) -> Option<&'static str> {
    if value.contains('^') {
        return Some("`^` would start a new query term");
    }
    if value.contains(['\r', '\n', '\0']) {
        return Some("line breaks and NUL are not allowed");
    }
    if value.to_ascii_lowercase().contains("javascript:") {
        return Some("`javascript:` would run server-side script");
    }
    if in_list && value.contains(',') {
        return Some("`,` would split an IN-list value");
    }
    None
}

fn reject(value: &str, why: &str) -> SncfrError {
    SncfrError::InvalidQueryValue {
        value: clean(value).chars().take(80).collect(),
        reason: why.to_string(),
    }
}

/// Checks a value before it is interpolated into an encoded query (`field=value`).
pub fn query_value(value: &str) -> Result<&str, SncfrError> {
    match query_value_problem(value, false) {
        Some(why) => Err(reject(value, why)),
        None => Ok(value),
    }
}

/// Like [`query_value`], for a value inside an `IN` list (also rejects `,`).
pub fn query_list_value(value: &str) -> Result<&str, SncfrError> {
    match query_value_problem(value, true) {
        Some(why) => Err(reject(value, why)),
        None => Ok(value),
    }
}

/// True when `value` contains `,` (callers then use `^OR` chains instead of `IN`).
pub fn needs_or_chain(value: &str) -> bool {
    value.contains(',')
}

/// A ServiceNow table name that may appear in a request path.
pub fn is_table_name(s: &str) -> bool {
    crate::pack::validate::is_table_name(s)
}

/// A 32-hex sys_id.
pub fn is_sys_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A record identifier segment: a sys_id in practice; letters, digits, and `_` only.
fn is_record_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Validates the table segment of `/api/now/table/<t>[/<sys_id>]`, `/api/now/stats/<t>`, and
/// `/api/now/attachment/...` style paths before a request is built. Also rejects path traversal
/// and protocol-relative forms anywhere in the path.
pub fn check_api_path(path: &str) -> Result<(), SncfrError> {
    let bare = path.split(['?', '#']).next().unwrap_or(path);
    let bad = |why: &str| SncfrError::InvalidArgs {
        message: format!("Refusing request path '{}': {why}", clean(bare)),
        remediation: Some(
            "Table names may contain only lowercase letters, digits, and `_`.".to_string(),
        ),
    };
    if bare.starts_with("//")
        || bare.contains("://")
        || bare.split('/').any(|seg| seg == ".." || seg == ".")
    {
        return Err(bad("path traversal or absolute URL"));
    }
    for prefix in ["/api/now/table/", "/api/now/stats/"] {
        if let Some(rest) = bare.strip_prefix(prefix) {
            let mut segs = rest.split('/');
            let table = segs.next().unwrap_or_default();
            if !is_table_name(table) {
                return Err(bad("invalid table name"));
            }
            if let Some(id) = segs.next()
                && !(prefix == "/api/now/table/" && is_record_id(id) && segs.next().is_none())
            {
                return Err(bad("unexpected path segments after the table name"));
            }
        }
    }
    Ok(())
}

fn is_dangerous(c: char) -> bool {
    if matches!(c, '\n' | '\t') {
        return false;
    }
    if ('\u{E0000}'..='\u{E007F}').contains(&c) {
        return true;
    }
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::Surrogate
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

/// Removes control (incl. ESC and C1), format (bidi overrides, zero-width), private-use,
/// unassigned, and tag characters, plus U+2028/2029. Keeps `\n` and `\t`. Normalizes `\r\n`
/// and lone `\r` to `\n`.
pub fn clean(s: &str) -> String {
    s.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|c| !is_dangerous(*c))
        .collect()
}

/// [`clean`] for a single-line context (a table cell, a list item): line breaks become `⏎`,
/// `|` is escaped, backticks and `<!--` are neutralized so the value can't open code spans or
/// HTML comments.
pub fn inline(s: &str) -> String {
    clean(s)
        .replace('\n', " ⏎ ")
        .replace('\t', " ")
        .replace('|', "\\|")
        .replace('`', "ʼ")
        .replace("<!--", "<!−−")
}

/// [`inline`], truncated to `max` characters (with `…`).
pub fn inline_truncated(s: &str, max: usize) -> String {
    let v = inline(s);
    if v.chars().count() <= max {
        v
    } else {
        let mut t: String = v.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Wraps multi-line untrusted text in a fenced block whose fence is longer than any backtick run
/// in the content, so the content can't close it.
pub fn fenced_block(s: &str) -> String {
    let body = clean(s);
    let mut longest = 0;
    let mut run = 0;
    for c in body.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}text\n{}\n{fence}", body.trim_end_matches('\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_cannot_add_or_reorder_terms() {
        assert!(query_value("Storage - L2").is_ok());
        assert!(query_value("Ops, EMEA - L2").is_ok());
        for bad in [
            "Nope^ORname=Payroll",
            "a\nb",
            "JavaScript:gs.getUserID()",
            "x\0",
        ] {
            let err = query_value(bad).unwrap_err();
            assert_eq!(err.code().as_str(), "INVALID_QUERY_VALUE");
            assert_eq!(err.code().exit_code(), 2);
        }
        assert!(query_list_value("Ops, EMEA - L2").is_err());
        assert!(needs_or_chain("Ops, EMEA - L2"));
    }

    #[test]
    fn api_paths_only_take_plain_table_names() {
        // CT-69
        assert!(check_api_path("/api/now/table/incident?sysparm_limit=1").is_ok());
        assert!(check_api_path("/api/now/table/incident/0123456789abcdef0123456789abcdef").is_ok());
        assert!(check_api_path("/api/now/stats/u_abc_request?sysparm_count=true").is_ok());
        assert!(check_api_path("/api/now/batch").is_ok());
        for bad in [
            "/api/now/table/../sys_user",
            "/api/now/table/x/y/z",
            "/api/now/table/Incident",
            "//evil.example/api",
            "https://evil.example/api/now/table/incident",
            "/api/now/table/incident/not-a-sys-id",
            "/api/now/table/incident/a%2F..",
        ] {
            assert!(check_api_path(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn clean_strips_controls_escapes_bidi_and_tag_characters() {
        // CT-45d (+ the terminal-escape half of CT-45b)
        let hostile = "Net\u{1b}[1A\u{1b}[2Kwork\u{1b}]52;c;Zm9v\u{7}\u{202E}\u{200B}\u{E0041}\u{2028}\u{9b}ok";
        let out = clean(hostile);
        assert!(!out.contains('\u{1b}'));
        assert!(!out.chars().any(|c| ('\u{80}'..='\u{9f}').contains(&c)));
        for c in ['\u{202E}', '\u{200B}', '\u{E0041}', '\u{2028}', '\u{7}'] {
            assert!(!out.contains(c), "{c:?} survived");
        }
        assert!(out.starts_with("Net") && out.ends_with("ok"));
        assert_eq!(clean("a\r\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn inline_values_cannot_create_markdown_structure() {
        let v = inline("x\n## Ignore previous | forged | cell `code` <!-- sncfr:overlay");
        assert!(!v.contains('\n'));
        assert!(!v.contains(" | "));
        assert!(!v.contains('`'));
        assert!(!v.contains("<!--"));
        assert_eq!(inline_truncated("abcdef", 4), "abc…");
    }

    #[test]
    fn fenced_blocks_outrun_embedded_backticks() {
        let block = fenced_block("before\n````\n## not a heading\nafter");
        assert!(block.starts_with("`````text\n"));
        assert!(block.ends_with("\n`````"));
    }
}
