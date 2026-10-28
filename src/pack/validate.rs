//! Semantic validation of a user Instance Pack (PACK-5), beyond what strict parsing catches.

use super::PackProblem;
use super::merged::MergedPack;
use super::schema::{PackFile, PackStatus, RecipeStep};
use std::collections::{BTreeMap, BTreeSet};

/// Problems found in a pack: `errors` make it unusable, `warnings` are advisory.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Findings {
    pub errors: Vec<PackProblem>,
    pub warnings: Vec<PackProblem>,
}

/// Table names that may be put into a request path (NA-13).
pub fn is_table_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Why an encoded-query fragment from a pack is unsafe to splice into a query, if it is.
pub fn encoded_query_fragment_problem(q: &str) -> Option<String> {
    let lower = q.to_ascii_lowercase();
    for (needle, why) in [
        (
            "^nq",
            "`^NQ` starts a new OR-query that widens the result set",
        ),
        ("^eq", "`^EQ` ends the query early"),
        (
            "rlquery",
            "related-list subqueries (`RLQUERY`) are not allowed",
        ),
        ("javascript:", "`javascript:` runs server-side script"),
        ("dynamic", "`DYNAMIC` runs a server-side dynamic filter"),
    ] {
        if lower.contains(needle) {
            return Some(why.to_string());
        }
    }
    if q.contains('\n') || q.contains('\r') {
        return Some("line breaks are not allowed".to_string());
    }
    if q.starts_with('^') || q.ends_with('^') {
        return Some("must not start or end with `^`".to_string());
    }
    for term in q.split('^') {
        let body = term.strip_prefix("OR").unwrap_or(term);
        let field_len = body
            .bytes()
            .take_while(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'.'
            })
            .count();
        if term.is_empty() || field_len == 0 {
            return Some(format!("term `{term}` does not start with a field name"));
        }
    }
    None
}

fn marker_ok(m: &str) -> bool {
    (1..=32).contains(&m.chars().count())
        && m.chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.:[]-".contains(c))
        && !m.to_ascii_lowercase().contains("[code]")
}

fn suffix_ok(s: &str) -> bool {
    (1..=32).contains(&s.chars().count()) && s.starts_with([' ', '-', '_', '/'])
}

/// Best-effort source location for a dotted key path: the most specific `[header]` that
/// matches, then the line declaring the next key inside it.
fn locate(text: &str, path: &[&str]) -> (usize, usize) {
    let lines: Vec<&str> = text.lines().collect();
    let header_of = |l: &str| {
        let t = l.trim();
        t.strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .map(|h| h.trim_matches(['[', ']']).trim().to_string())
    };
    for depth in (1..=path.len()).rev() {
        let want = path[..depth].join(".");
        if let Some(idx) = lines
            .iter()
            .position(|l| header_of(l).as_deref() == Some(want.as_str()))
        {
            if let Some(next) = path.get(depth) {
                for (j, l) in lines.iter().enumerate().skip(idx + 1) {
                    if header_of(l).is_some() {
                        break;
                    }
                    if let Some(col) = l.find(next) {
                        return (j + 1, col + 1);
                    }
                }
            }
            return (idx + 1, 1);
        }
    }
    if let Some(last) = path.last() {
        for (j, l) in lines.iter().enumerate() {
            if let Some(col) = l.find(last) {
                return (j + 1, col + 1);
            }
        }
    }
    (1, 1)
}

struct Collector<'a> {
    text: &'a str,
    out: Findings,
}

impl Collector<'_> {
    fn push(&mut self, warning: bool, path: &[&str], message: String) {
        let (line, col) = locate(self.text, path);
        let problem = PackProblem {
            line,
            col,
            message: format!("{}: {message}", path.join(".")),
        };
        if warning {
            self.out.warnings.push(problem);
        } else {
            self.out.errors.push(problem);
        }
    }
    fn error(&mut self, path: &[&str], message: impl Into<String>) {
        self.push(false, path, message.into());
    }
    fn warn(&mut self, path: &[&str], message: impl Into<String>) {
        self.push(true, path, message.into());
    }
    fn table(&mut self, path: &[&str], name: &str) {
        if !is_table_name(name) {
            self.error(
                path,
                format!("`{name}` is not a valid table name (lowercase letters, digits, `_`)"),
            );
        }
    }
}

/// Placeholders (`{name}` or `{step.field}`) in a recipe template.
fn placeholders(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        out.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// Validates a parsed user pack. `ootb` is used for warnings about `[remove]` targets.
pub fn validate_user_pack(text: &str, file: &PackFile, ootb: &MergedPack) -> Findings {
    let mut c = Collector {
        text,
        out: Findings::default(),
    };

    match file.status {
        PackStatus::Active if file.instances.is_empty() => c.error(
            &["instances"],
            "an active pack must list the instance hosts it describes (e.g. instances = [\"mycompany.service-now.com\"])",
        ),
        PackStatus::Draft => c.warn(
            &["status"],
            "draft: review each \"# observed\" entry, add values not seen, then set status = \"active\" to use this pack for writes",
        ),
        PackStatus::Active => {}
    }

    if let Some(core) = &file.core
        && core.known_free_text.is_some()
    {
        c.error(&["core", "known_free_text"], "only the bundled ootb pack may set known_free_text (marking a field free text bypasses write validation)");
    }

    if let Some(prefixes) = &file.prefixes {
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for (k, table) in prefixes {
            let upper = k.to_ascii_uppercase();
            if !(1..=16).contains(&upper.len())
                || !upper.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            {
                c.error(&["prefixes", k], "prefix must be 1-16 letters or `_`");
            }
            if let Some(prev) = seen.insert(upper.clone(), k) {
                c.error(
                    &["prefixes", k],
                    format!("duplicate prefix (also `{prev}`)"),
                );
            }
            c.table(&["prefixes", k], table);
        }
    }

    if let Some(h) = &file.hierarchy {
        for (child, parent) in h {
            c.table(&["hierarchy", child], child);
            c.table(&["hierarchy", child], parent);
        }
    }

    if let Some(choices) = &file.choices {
        for (table, fields) in choices {
            c.table(&["choices", table], table);
            for (field, set) in fields {
                let path = ["choices", table.as_str(), field.as_str()];
                let mut names: BTreeMap<String, &str> = BTreeMap::new();
                for entry in &set.values {
                    for name in std::iter::once(&entry.label).chain(&entry.aliases) {
                        let key = name.trim().to_lowercase();
                        if let Some(prev) = names.insert(key, entry.value.as_str())
                            && prev != entry.value
                        {
                            c.error(
                                &path,
                                format!(
                                    "`{name}` names both value `{prev}` and value `{}`",
                                    entry.value
                                ),
                            );
                        }
                    }
                }
                if !set.confirm_required {
                    c.warn(
                        &path,
                        format!(
                            "{} values; values not listed here are rejected",
                            set.values.len()
                        ),
                    );
                }
            }
        }
    }

    for (section, rules) in [
        ("open_rule", &file.open_rule),
        ("closed_rule", &file.closed_rule),
    ] {
        for (table, rule) in rules.iter().flatten() {
            c.table(&[section, table], table);
            if let Some(why) = encoded_query_fragment_problem(&rule.query) {
                c.error(&[section, table, "query"], why);
            }
        }
    }

    if let Some(groups) = &file.groups {
        for s in &groups.suffixes {
            if !suffix_ok(s) {
                c.error(
                    &["groups", "suffixes"],
                    format!(
                        "suffix `{s}` must be 1-32 chars and start with a space, `-`, `_` or `/`"
                    ),
                );
            }
        }
    }

    if let Some(fields) = &file.fields {
        for table in fields.default.keys() {
            c.table(&["fields", "default", table], table);
        }
    }

    if let Some(d) = &file.discovery {
        for (table, fs) in &d.choice_fields {
            c.table(&["discovery", "choice_fields", table], table);
            for f in fs {
                if ootb.core.known_free_text.contains(f)
                    || ootb.core.caller_fields.values().any(|cf| cf == f)
                {
                    c.warn(
                        &["discovery", "choice_fields", table],
                        format!("`{f}` is not a choice field; it will not be probed"),
                    );
                }
            }
        }
    }

    for (name, recipe) in file.recipes.iter().flatten() {
        let params: BTreeSet<&str> = recipe.params.iter().map(String::as_str).collect();
        let mut earlier: BTreeSet<&str> = BTreeSet::new();
        for step in &recipe.steps {
            let path = ["recipes", name.as_str(), step.id()];
            let templates: Vec<&str> = match step {
                RecipeStep::Table { table, query, .. } | RecipeStep::Stats { table, query, .. } => {
                    if table.contains('{') {
                        c.error(
                            &path,
                            "substitution is only allowed in `query` and `ticket`",
                        );
                    } else {
                        c.table(&path, table);
                    }
                    let literal: String =
                        placeholders(query).iter().fold(query.clone(), |acc, p| {
                            acc.replace(&format!("{{{p}}}"), "x")
                        });
                    if let Some(why) = encoded_query_fragment_problem(&literal) {
                        c.error(&path, format!("query: {why}"));
                    }
                    vec![query.as_str()]
                }
                RecipeStep::Show { ticket, .. } => vec![ticket.as_str()],
            };
            for t in templates {
                for p in placeholders(t) {
                    match p.split_once('.') {
                        Some((step_id, _)) if earlier.contains(step_id) => {}
                        Some((step_id, _)) => c.error(
                            &path,
                            format!(
                                "`{{{p}}}` refers to step `{step_id}`, which is not an earlier step"
                            ),
                        ),
                        None if params.contains(p.as_str()) => {}
                        None => c.error(&path, format!("`{{{p}}}` is not a declared param")),
                    }
                }
            }
            if !earlier.insert(step.id()) {
                c.error(&path, "duplicate step id");
            }
        }
    }

    if let Some(audit) = &file.audit
        && let Some(m) = &audit.agent_write_marker
        && !marker_ok(m)
    {
        c.error(&["audit", "agent_write_marker"], "marker must be 1-32 chars of letters, digits, space, `_.:[]-`, and must not contain `[code]`");
    }

    if let Some(triage) = &file.triage {
        for (name, b) in &triage.custom {
            c.table(&["triage", "custom", name], &b.table);
            if let Some(why) = encoded_query_fragment_problem(&b.query) {
                c.error(&["triage", "custom", name], format!("query: {why}"));
            }
        }
    }

    if let Some(r) = &file.remove {
        let defined = |set: bool| set;
        for k in &r.prefixes {
            let upper = k.to_ascii_uppercase();
            let here = file
                .prefixes
                .as_ref()
                .is_some_and(|p| p.keys().any(|pk| pk.to_ascii_uppercase() == upper));
            if !defined(ootb.prefixes.contains_key(&upper) || here) {
                c.warn(
                    &["remove", "prefixes"],
                    format!("`{k}` is not defined by any layer"),
                );
            }
        }
        for k in &r.choices {
            if !ootb.choices.contains_key(k) {
                c.warn(
                    &["remove", "choices"],
                    format!("`{k}` is not defined by the ootb pack"),
                );
            }
        }
    }

    c.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{active, parse_pack};

    const HEAD: &str = "schema_version = 1\npack_version = \"1\"\nname = \"t\"\ninstances = [\"example.service-now.com\"]\n";

    fn findings(body: &str) -> Findings {
        let text = format!("{HEAD}{body}");
        let file = parse_pack(&text).expect("parse");
        validate_user_pack(&text, &file, active())
    }

    fn assert_error(body: &str, needle: &str) {
        let f = findings(body);
        assert!(
            f.errors.iter().any(|e| e.message.contains(needle)),
            "expected error containing `{needle}`, got {:?}",
            f.errors
        );
    }

    #[test]
    fn valid_pack_has_no_errors() {
        let f = findings("[prefixes]\nABC = \"u_abc_request\"\n[groups]\nsuffixes = [\" - L2\"]\n");
        assert!(f.errors.is_empty(), "{:?}", f.errors);
    }

    #[test]
    fn rejects_alias_naming_two_values_and_bad_suffix_marker_and_rules() {
        // CT-05
        assert_error(
            "[choices.incident.priority]\nvalues = [\n  { value = \"4\", label = \"4 - Minor\", aliases = [\"low\"] },\n  { value = \"5\", label = \"5 - Low\", aliases = [\"low\"] },\n]\n",
            "`low` names both value `4` and value `5`",
        );
        assert_error("[groups]\nsuffixes = [\"work\"]\n", "suffix `work`");
        assert_error(
            "[audit]\nagent_write_marker = \"[code]<b>x</b>[/code]\"\n",
            "agent_write_marker",
        );
        assert_error(
            "[open_rule.incident]\nquery = \"active=true^NQsys_idISNOTEMPTY\"\n",
            "`^NQ`",
        );
        assert_error(
            "[open_rule.incident]\nquery = \"javascript:gs.getUserID()\"\n",
            "`javascript:`",
        );
    }

    #[test]
    fn rejects_known_free_text_in_user_pack() {
        // CT-64
        assert_error(
            "[core]\nknown_free_text = [\"priority\"]\n",
            "known_free_text",
        );
    }

    #[test]
    fn rejects_bad_table_names_and_duplicate_prefixes() {
        assert_error(
            "[prefixes]\nABC = \"../sys_user\"\n",
            "not a valid table name",
        );
        assert_error(
            "[prefixes]\nabc = \"u_a\"\nABC = \"u_b\"\n",
            "duplicate prefix",
        );
    }

    #[test]
    fn rejects_mutating_or_unsafe_recipe_steps() {
        // CT-32 (the closed step enum rejects `kind = "update"` at parse time; see pack::tests)
        assert_error(
            "[recipes.r]\nparams = [\"t\"]\nsteps = [{ kind = \"table\", id = \"a\", table = \"{t}\", query = \"\" }]\n",
            "substitution is only allowed",
        );
        assert_error(
            "[recipes.r]\nsteps = [{ kind = \"table\", id = \"a\", table = \"incident\", query = \"number={missing}\" }]\n",
            "not a declared param",
        );
        assert_error(
            "[recipes.r]\nsteps = [\n  { kind = \"table\", id = \"a\", table = \"incident\", query = \"x={b.sys_id}\" },\n  { kind = \"table\", id = \"b\", table = \"incident\", query = \"\" },\n]\n",
            "not an earlier step",
        );
    }

    #[test]
    fn active_pack_requires_instances_and_draft_warns() {
        let text = "schema_version = 1\npack_version = \"1\"\nname = \"t\"\n";
        let f = validate_user_pack(text, &parse_pack(text).unwrap(), active());
        assert!(f.errors.iter().any(|e| e.message.starts_with("instances")));
        let draft = format!("{text}status = \"draft\"\n");
        let f = validate_user_pack(&draft, &parse_pack(&draft).unwrap(), active());
        assert!(f.errors.is_empty());
        assert!(f.warnings.iter().any(|w| w.message.contains("draft")));
    }

    #[test]
    fn complete_set_notice_and_located_problems() {
        let f = findings(
            "[choices.incident.priority]\nvalues = [{ value = \"5\", label = \"5 - Low\" }]\n",
        );
        assert!(f.warnings.iter().any(|w| {
            w.message
                .contains("1 values; values not listed here are rejected")
        }));
        let f = findings("[groups]\nsuffixes = [\"work\"]\n");
        assert_eq!(f.errors[0].line, 6, "{:?}", f.errors);
    }

    #[test]
    fn query_fragment_rules() {
        assert!(encoded_query_fragment_problem("active=true^stateNOT IN6,7,8").is_none());
        assert!(encoded_query_fragment_problem("caller_id.vip=true^ORpriority=1").is_none());
        assert!(encoded_query_fragment_problem("^active=true").is_some());
        assert!(encoded_query_fragment_problem("active=true^EQ").is_some());
        assert!(encoded_query_fragment_problem("=true").is_some());
    }
}
