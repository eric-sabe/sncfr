use crate::cache::CachedIdentity;
use crate::cli::ListFilterArgs;
use crate::config::SavedView;
use crate::error::SncfrError;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, Utc};
use url::Url;

/// Standard ServiceNow Dynamic Filter Option `sys_id` for "Me" (`gs.getUserID()`).
pub const DYNAMIC_ME_SYS_ID: &str = "90d1921e5f510100a9ad2572f2b477fe";

/// Standard ServiceNow Dynamic Filter Option `sys_id` for "One of My Groups" (`getMyGroups()`).
pub const DYNAMIC_MY_GROUPS_SYS_ID: &str = "d6435e965f510100a9ad2572f2b47744";

/// Strongly-typed fluent builder for ServiceNow encoded query strings (`sysparm_query`).
///
/// Reference: `ServiceNow/ServiceNowDocs` -> `c_EncodedQueryStrings.md` & `r_OpAvailableFiltersQueries.md`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncodedQuery {
    clauses: Vec<String>,
    orders: Vec<String>,
}

impl EncodedQuery {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if neither filter clauses nor sort clauses have been added.
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty() && self.orders.is_empty()
    }

    /// Adds an exact match condition (`field=value`).
    pub fn equals(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}={value}"));
        self
    }

    /// Adds an inequality condition (`field!=value`).
    pub fn not_equals(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}!={value}"));
        self
    }

    /// Adds a substring containment condition (`fieldLIKEvalue`).
    pub fn like(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}LIKE{value}"));
        self
    }

    /// Adds a prefix match condition (`fieldSTARTSWITHvalue`).
    pub fn starts_with(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}STARTSWITH{value}"));
        self
    }

    /// Adds a suffix match condition (`fieldENDSWITHvalue`).
    pub fn ends_with(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}ENDSWITH{value}"));
        self
    }

    /// Adds a set membership condition (`fieldINv1,v2,...`).
    pub fn in_list<I, S>(&mut self, field: &str, values: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let joined: Vec<String> = values
            .into_iter()
            .map(|v| v.as_ref().trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !joined.is_empty() {
            self.clauses.push(format!("{field}IN{}", joined.join(",")));
        }
        self
    }

    /// Adds an `ISEMPTY` condition (`fieldISEMPTY`).
    pub fn is_empty_field(&mut self, field: &str) -> &mut Self {
        self.clauses.push(format!("{field}ISEMPTY"));
        self
    }

    /// Adds an `ISNOTEMPTY` condition (`fieldISNOTEMPTY`).
    pub fn is_not_empty_field(&mut self, field: &str) -> &mut Self {
        self.clauses.push(format!("{field}ISNOTEMPTY"));
        self
    }

    /// Adds a greater-than-or-equal condition (`field>=value`).
    pub fn gte(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}>={value}"));
        self
    }

    /// Adds a less-than-or-equal condition (`field<=value`).
    pub fn lte(&mut self, field: &str, value: &str) -> &mut Self {
        self.clauses.push(format!("{field}<={value}"));
        self
    }

    /// Adds a ServiceNow `DYNAMIC` condition (`fieldDYNAMIC<filter_option_sys_id>`).
    pub fn dynamic(&mut self, field: &str, dynamic_sys_id: &str) -> &mut Self {
        self.clauses.push(format!("{field}DYNAMIC{dynamic_sys_id}"));
        self
    }

    /// Adds a full-text search index condition (`123TEXTQUERY321=<phrase>`).
    pub fn text_query(&mut self, phrase: &str) -> &mut Self {
        self.clauses.push(format!("123TEXTQUERY321={phrase}"));
        self
    }

    /// Chains an `^OR` condition onto the most recent clause (or adds it as the first clause if empty).
    pub fn or_raw(&mut self, raw_condition: &str) -> &mut Self {
        let cleaned = strip_trailing_eq(raw_condition);
        if cleaned.is_empty() {
            return self;
        }
        if let Some(last) = self.clauses.last_mut() {
            last.push_str("^OR");
            last.push_str(cleaned);
        } else {
            self.clauses.push(cleaned.to_string());
        }
        self
    }

    /// Appends a raw ServiceNow encoded query fragment (stripping leading/trailing `^` and `^EQ`).
    pub fn raw(&mut self, raw_query: &str) -> &mut Self {
        let cleaned = strip_trailing_eq(raw_query);
        if !cleaned.is_empty() {
            self.clauses.push(cleaned.to_string());
        }
        self
    }

    /// Appends an ascending sort (`ORDERBY<field>`).
    pub fn order_by(&mut self, field: &str) -> &mut Self {
        self.orders.push(format!("ORDERBY{field}"));
        self
    }

    /// Appends a descending sort (`ORDERBYDESC<field>`).
    pub fn order_by_desc(&mut self, field: &str) -> &mut Self {
        self.orders.push(format!("ORDERBYDESC{field}"));
        self
    }

    /// Renders the complete `sysparm_query` string.
    pub fn build(&self) -> String {
        let mut parts = Vec::with_capacity(self.clauses.len() + self.orders.len());
        parts.extend(self.clauses.iter().cloned());
        parts.extend(self.orders.iter().cloned());
        parts.join("^")
    }
}

fn strip_trailing_eq(raw: &str) -> &str {
    let mut s = raw.trim().trim_matches('^');
    while let Some(stripped) = s.strip_suffix("^EQ") {
        s = stripped.trim_end_matches('^');
    }
    if s == "EQ" { "" } else { s }
}

/// Parses a relative duration (`15m`, `4h`, `2d`, `1w`) or ISO date/timestamp (`2026-10-20`,
/// `2026-10-20T14:30:00Z`, `2026-10-20 14:30:00`) against `now` and returns a UTC [`DateTime<Utc>`].
pub fn parse_since_to_utc(input: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, SncfrError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "Duration or timestamp cannot be empty".to_string(),
            remediation: Some(
                "Use a relative duration like `30m`, `4h`, `2d`, `1w` or an ISO date like `2026-10-20`."
                    .to_string(),
            ),
        });
    }

    // 1. Check relative duration suffix: s, m, h, d, w
    if let Some((num_str, unit)) = split_duration_unit(s)
        && let Ok(amount) = num_str.parse::<i64>()
        && amount > 0
    {
        let delta = match unit {
            "s" => Duration::seconds(amount),
            "m" => Duration::minutes(amount),
            "h" => Duration::hours(amount),
            "d" => Duration::days(amount),
            "w" => Duration::weeks(amount),
            _ => unreachable!(),
        };
        return Ok(now - delta);
    }

    // 2. Check RFC3339 / ISO 8601 timestamp with timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // 3. Check `YYYY-MM-DD HH:MM:SS` (ServiceNow UTC format) or `YYYY-MM-DDTHH:MM:SS`
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(naive_dt.and_utc());
        }
    }

    // 4. Check `YYYY-MM-DD` date
    if let Ok(naive_date) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        && let Some(naive_dt) = naive_date.and_hms_opt(0, 0, 0)
    {
        return Ok(naive_dt.and_utc());
    }

    Err(SncfrError::InvalidArgs {
        message: format!("Invalid relative duration or timestamp '{input}'"),
        remediation: Some(
            "Expected a relative duration (`15m`, `4h`, `2d`, `1w`) or ISO date/timestamp (`2026-10-20` or `2026-10-20T14:30:00Z`)."
                .to_string(),
        ),
    })
}

fn split_duration_unit(s: &str) -> Option<(&str, &str)> {
    for unit in ["s", "m", "h", "d", "w"] {
        if let Some(num) = s.strip_suffix(unit)
            && !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit())
        {
            return Some((num, unit));
        }
    }
    None
}

/// Formats a [`DateTime<Utc>`] into ServiceNow's standard GMT query format (`YYYY-MM-DD HH:MM:SS`).
pub fn format_servicenow_gmt(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Result of parsing a pasted ServiceNow UI or REST URL (`--from-url`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServiceNowUrl {
    /// Base instance URL (`https://<host>`) if a full URL was supplied.
    pub instance_url: Option<Url>,
    /// Resolved target table name (e.g., `"incident"`, `"sc_req_item"`, `"change_request"`).
    pub table: String,
    /// Decoded `sysparm_query` (or `sys_id=<id>` for single-record URLs).
    pub query: Option<String>,
    /// Optional `sysparm_view` extracted from the URL.
    pub view: Option<String>,
}

/// Parses a pasted ServiceNow browser or API URL into its target table and encoded query.
///
/// Supports:
/// 1. Classic list URLs: `https://example.service-now.com/incident_list.do?sysparm_query=active%3Dtrue`
/// 2. Classic `nav_to.do?uri=...` wrapper URLs
/// 3. Next Experience (`Polaris`) URLs: `https://example.service-now.com/now/nav/ui/classic/params/target/incident_list.do%3Fsysparm_query%3D...`
/// 4. Classic record form URLs: `https://example.service-now.com/incident.do?sys_id=...`
/// 5. Service Portal ticket URLs: `https://example.service-now.com/sp?id=ticket&table=incident&sys_id=...`
/// 6. REST Table API URLs: `https://example.service-now.com/api/now/table/incident?sysparm_query=...`
pub fn parse_servicenow_url(raw_url: &str) -> Result<ParsedServiceNowUrl, SncfrError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(SncfrError::InvalidArgs {
            message: "`--from-url` value cannot be empty".to_string(),
            remediation: None,
        });
    }

    let (instance_url, parsed) =
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let u = Url::parse(trimmed).map_err(|e| SncfrError::InvalidArgs {
                message: format!("Invalid ServiceNow URL '{raw_url}': {e}"),
                remediation: None,
            })?;
            let mut base = u.clone();
            base.set_path("");
            base.set_query(None);
            base.set_fragment(None);
            (Some(base), u)
        } else {
            let synthetic = format!(
                "https://example.service-now.com/{}",
                trimmed.trim_start_matches('/')
            );
            let u = Url::parse(&synthetic).map_err(|e| SncfrError::InvalidArgs {
                message: format!("Invalid ServiceNow URL path '{raw_url}': {e}"),
                remediation: None,
            })?;
            (None, u)
        };

    // Unwrap Next Experience `/now/nav/ui/classic/params/target/<encoded-inner>`
    let path = parsed.path();
    if let Some(encoded_target) = path.strip_prefix("/now/nav/ui/classic/params/target/") {
        let decoded_target = percent_decode(encoded_target);
        let inner_url = format!(
            "https://example.service-now.com/{}",
            decoded_target.trim_start_matches('/')
        );
        let mut result = parse_servicenow_url(&inner_url)?;
        result.instance_url = instance_url;
        return Ok(result);
    }

    // Unwrap Classic `/nav_to.do?uri=<encoded-inner>`
    if path.ends_with("/nav_to.do")
        && let Some((_, uri_val)) = parsed.query_pairs().find(|(k, _)| k == "uri")
    {
        let inner_url = format!(
            "https://example.service-now.com/{}",
            uri_val.trim_start_matches('/')
        );
        let mut result = parse_servicenow_url(&inner_url)?;
        result.instance_url = instance_url;
        return Ok(result);
    }

    let mut sysparm_query: Option<String> = None;
    let mut sysparm_view: Option<String> = None;
    let mut sys_id: Option<String> = None;
    let mut query_table: Option<String> = None;

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "sysparm_query" if !v.trim().is_empty() => {
                let cleaned = strip_trailing_eq(&v).to_string();
                if !cleaned.is_empty() {
                    sysparm_query = Some(cleaned);
                }
            }
            "sysparm_view" if !v.trim().is_empty() => {
                sysparm_view = Some(v.into_owned());
            }
            "sys_id" if !v.trim().is_empty() && v != "-1" => {
                sys_id = Some(v.into_owned());
            }
            "table" if !v.trim().is_empty() => {
                query_table = Some(v.into_owned());
            }
            _ => {}
        }
    }

    let table = extract_table_from_path(path)
        .or(query_table)
        .ok_or_else(|| SncfrError::InvalidArgs {
            message: format!(
                "Could not determine target ServiceNow table from URL '{raw_url}'"
            ),
            remediation: Some(
                "Expected a ServiceNow list/form URL (e.g., `.../incident_list.do?sysparm_query=...` or `/now/nav/ui/classic/params/target/...`)."
                    .to_string(),
            ),
        })?;

    let query = match (sysparm_query, sys_id) {
        (Some(q), _) => Some(q),
        (None, Some(id)) => Some(format!("sys_id={id}")),
        (None, None) => None,
    };

    Ok(ParsedServiceNowUrl {
        instance_url,
        table,
        query,
        view: sysparm_view,
    })
}

fn extract_table_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('/');

    // REST Table API: `/api/now/table/{table}` or `/api/now/v1/table/{table}`
    let segments: Vec<&str> = trimmed.split('/').collect();
    if let Some(table_idx) = segments.iter().position(|&seg| seg == "table")
        && let Some(&table_seg) = segments.get(table_idx + 1)
        && !table_seg.is_empty()
    {
        return Some(table_seg.to_lowercase());
    }

    // Classic UI: `<table_name>_list.do` or `<table_name>.do`
    let last_segment = segments.last().copied().unwrap_or("");
    if let Some(table) = last_segment.strip_suffix("_list.do")
        && !table.is_empty()
    {
        return Some(table.to_lowercase());
    }
    if let Some(table) = last_segment.strip_suffix(".do")
        && !table.is_empty()
        && table != "nav_to"
        && table != " navpage"
        && table != "$sp"
    {
        return Some(table.to_lowercase());
    }

    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Resolves a table shorthand or prefix (`inc`, `ritm`, `chg`, `sctask`, `prb`, `req`, `cs`) to its canonical table name.
pub fn resolve_table_shorthand(table_or_prefix: &str) -> String {
    crate::pack::active().resolve_table_shorthand(table_or_prefix)
}

/// Compiles [`ListFilterArgs`], an optional [`SavedView`], and optional [`CachedIdentity`] into
/// a concrete `(table_name, sysparm_query)` pair.
pub fn compile_list_filters(
    filters: &ListFilterArgs,
    saved_view: Option<&SavedView>,
    identity: Option<&CachedIdentity>,
    now: DateTime<Utc>,
) -> Result<(String, EncodedQuery), SncfrError> {
    let mut eq = EncodedQuery::new();
    let mut resolved_table: Option<String> = None;

    // 1. Seed from saved view if provided
    if let Some(view) = saved_view {
        resolved_table = Some(resolve_table_shorthand(&view.table));
        eq.raw(&view.query);
    }

    // 2. Seed/merge from `--from-url` if provided
    if let Some(url_str) = &filters.from_url {
        let parsed_url = parse_servicenow_url(url_str)?;
        resolved_table = Some(parsed_url.table);
        if let Some(url_query) = parsed_url.query {
            eq.raw(&url_query);
        }
    }

    // 3. Explicit `--table` overrides saved view or URL table
    if let Some(explicit_table) = &filters.table {
        resolved_table = Some(resolve_table_shorthand(explicit_table));
    }

    let table = resolved_table.unwrap_or_else(|| "task".to_string());

    // 4. `--mine`: assigned_to=@me OR opened_by=@me (or caller_id / requested_for)
    if filters.mine {
        let me_val = identity
            .map(|id| format!("={}", id.sys_id))
            .unwrap_or_else(|| format!("DYNAMIC{DYNAMIC_ME_SYS_ID}"));
        let mut mine_clause = format!("assigned_to{me_val}^ORopened_by{me_val}");
        let caller_field = crate::pack::active().caller_field(&table);
        if caller_field != "opened_by" && caller_field != "assigned_to" {
            mine_clause.push_str(&format!("^OR{caller_field}{me_val}"));
        }
        eq.raw(&mine_clause);
    }

    // 5. `--assigned-to`
    if let Some(assigned) = &filters.assigned_to {
        let trimmed = assigned.trim();
        if trimmed.eq_ignore_ascii_case("unassigned") || trimmed.eq_ignore_ascii_case("none") {
            eq.is_empty_field("assigned_to");
        } else if trimmed.eq_ignore_ascii_case("@me") {
            if let Some(id) = identity {
                eq.equals("assigned_to", &id.sys_id);
            } else {
                eq.dynamic("assigned_to", DYNAMIC_ME_SYS_ID);
            }
        } else if is_sys_id(trimmed) {
            eq.equals("assigned_to", trimmed);
        } else if trimmed.contains('@') {
            eq.equals("assigned_to.email", trimmed);
        } else {
            eq.equals("assigned_to.user_name", trimmed);
        }
    }

    // 6. `--opened-by`
    if let Some(opener) = &filters.opened_by {
        let trimmed = opener.trim();
        if trimmed.eq_ignore_ascii_case("@me") {
            if let Some(id) = identity {
                eq.equals("opened_by", &id.sys_id);
            } else {
                eq.dynamic("opened_by", DYNAMIC_ME_SYS_ID);
            }
        } else if is_sys_id(trimmed) {
            eq.equals("opened_by", trimmed);
        } else if trimmed.contains('@') {
            eq.equals("opened_by.email", trimmed);
        } else {
            eq.equals("opened_by.user_name", trimmed);
        }
    }

    // 7. `--group`
    if let Some(group) = &filters.group {
        let trimmed = group.trim();
        if trimmed.eq_ignore_ascii_case("@my-groups") {
            if let Some(id) = identity
                && !id.groups.is_empty()
            {
                eq.in_list(
                    "assignment_group",
                    id.groups.iter().map(|g| g.sys_id.as_str()),
                );
            } else {
                eq.dynamic("assignment_group", DYNAMIC_MY_GROUPS_SYS_ID);
            }
        } else if is_sys_id(trimmed) {
            eq.equals("assignment_group", trimmed);
        } else {
            eq.equals("assignment_group.name", trimmed);
        }
    }

    // 8. `--watch-list`
    if let Some(watcher) = &filters.watch_list {
        let trimmed = watcher.trim();
        if trimmed.eq_ignore_ascii_case("@me") {
            if let Some(id) = identity {
                eq.like("watch_list", &id.sys_id);
            } else {
                eq.dynamic("watch_list", DYNAMIC_ME_SYS_ID);
            }
        } else {
            eq.like("watch_list", trimmed);
        }
    }

    // 9. `--active` / `--inactive`
    if filters.active {
        eq.equals("active", "true");
    } else if filters.inactive {
        eq.equals("active", "false");
    }

    // 10. `--state` and `--priority`
    if !filters.state.is_empty() {
        if filters.state.len() == 1 {
            eq.equals("state", &filters.state[0]);
        } else {
            eq.in_list("state", &filters.state);
        }
    }
    if !filters.priority.is_empty() {
        if filters.priority.len() == 1 {
            eq.equals("priority", &filters.priority[0]);
        } else {
            eq.in_list("priority", &filters.priority);
        }
    }

    // 11. `--updated-since` and `--created-since`
    if let Some(updated_since) = &filters.updated_since {
        let dt = parse_since_to_utc(updated_since, now)?;
        eq.gte("sys_updated_on", &format_servicenow_gmt(dt));
    }
    if let Some(created_since) = &filters.created_since {
        let dt = parse_since_to_utc(created_since, now)?;
        eq.gte("sys_created_on", &format_servicenow_gmt(dt));
    }

    // 12. Raw `--query`
    if let Some(raw_q) = &filters.query {
        eq.raw(raw_q);
    }

    // 13. Sorting (defaults to `ORDERBYDESCsys_updated_on` if no sort specified)
    if let Some(sort_field) = &filters.sort {
        if filters.asc {
            eq.order_by(sort_field);
        } else {
            eq.order_by_desc(sort_field);
        }
    } else if filters.asc {
        eq.order_by("sys_updated_on");
    } else if filters.desc {
        eq.order_by_desc("sys_updated_on");
    }

    Ok((table, eq))
}

/// Returns `true` if `s` is a 32-character hexadecimal ServiceNow `sys_id`.
pub fn is_sys_id(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedGroup;
    use chrono::TimeZone;

    #[test]
    fn builds_complex_encoded_queries_cleanly() {
        let mut q = EncodedQuery::new();
        q.equals("active", "true")
            .in_list("priority", ["1", "2"])
            .like("short_description", "VPN")
            .or_raw("descriptionLIKEVPN")
            .order_by_desc("sys_updated_on");

        assert_eq!(
            q.build(),
            "active=true^priorityIN1,2^short_descriptionLIKEVPN^ORdescriptionLIKEVPN^ORDERBYDESCsys_updated_on"
        );
    }

    #[test]
    fn parses_relative_durations_and_iso_timestamps() {
        let now = Utc.with_ymd_and_hms(2026, 10, 22, 18, 0, 0).unwrap();

        let minus_4h = parse_since_to_utc("4h", now).expect("4h");
        assert_eq!(format_servicenow_gmt(minus_4h), "2026-10-22 14:00:00");

        let minus_2d = parse_since_to_utc("2d", now).expect("2d");
        assert_eq!(format_servicenow_gmt(minus_2d), "2026-10-20 18:00:00");

        let iso_date = parse_since_to_utc("2026-10-15", now).expect("iso date");
        assert_eq!(format_servicenow_gmt(iso_date), "2026-10-15 00:00:00");

        let rfc3339 = parse_since_to_utc("2026-10-20T09:30:00Z", now).expect("rfc3339");
        assert_eq!(format_servicenow_gmt(rfc3339), "2026-10-20 09:30:00");
    }

    #[test]
    fn parses_classic_nav_to_and_next_experience_servicenow_urls() {
        // 1. Classic list URL
        let classic = parse_servicenow_url(
            "https://example.service-now.com/incident_list.do?sysparm_query=priority%3D1%5Eactive%3Dtrue%5EEQ&sysparm_view=itil",
        )
        .expect("classic url");
        assert_eq!(classic.table, "incident");
        assert_eq!(classic.query.as_deref(), Some("priority=1^active=true"));
        assert_eq!(classic.view.as_deref(), Some("itil"));

        // 2. Classic nav_to.do wrapper URL
        let nav_to = parse_servicenow_url(
            "https://example.service-now.com/nav_to.do?uri=%2Fsc_req_item_list.do%3Fsysparm_query%3Dactive%3Dtrue%26sysparm_view%3Dess",
        )
        .expect("nav_to url");
        assert_eq!(nav_to.table, "sc_req_item");
        assert_eq!(nav_to.query.as_deref(), Some("active=true"));
        assert_eq!(nav_to.view.as_deref(), Some("ess"));

        // 3. Next Experience (Polaris) URL
        let polaris = parse_servicenow_url(
            "https://example.service-now.com/now/nav/ui/classic/params/target/change_request_list.do%3Fsysparm_query%3Dstate%3D-5%5Eactive%3Dtrue%26sysparm_first_row%3D1",
        )
        .expect("polaris url");
        assert_eq!(polaris.table, "change_request");
        assert_eq!(polaris.query.as_deref(), Some("state=-5^active=true"));

        // 4. Single record form URL
        let form = parse_servicenow_url(
            "https://example.service-now.com/incident.do?sys_id=6816f79cc0a8016401c5a33be04be441",
        )
        .expect("form url");
        assert_eq!(form.table, "incident");
        assert_eq!(
            form.query.as_deref(),
            Some("sys_id=6816f79cc0a8016401c5a33be04be441")
        );
    }

    #[test]
    fn compiles_list_filters_with_cached_identity_and_saved_view() {
        let now = Utc.with_ymd_and_hms(2026, 10, 22, 18, 0, 0).unwrap();
        let identity = CachedIdentity {
            sys_id: "6816f79cc0a8016401c5a33be04be441".to_string(),
            user_name: "jane.doe".to_string(),
            display_name: "Jane Doe".to_string(),
            email: Some("jane.doe@example.com".to_string()),
            groups: vec![
                CachedGroup {
                    sys_id: "11111111111111111111111111111111".to_string(),
                    name: "Cloud Platform".to_string(),
                },
                CachedGroup {
                    sys_id: "22222222222222222222222222222222".to_string(),
                    name: "SRE".to_string(),
                },
            ],
        };

        let filters = ListFilterArgs {
            table: Some("inc".to_string()),
            assigned_to: Some("@me".to_string()),
            group: Some("@my-groups".to_string()),
            active: true,
            priority: vec!["1".to_string(), "2".to_string()],
            updated_since: Some("4h".to_string()),
            desc: true,
            ..Default::default()
        };

        let (table, eq) =
            compile_list_filters(&filters, None, Some(&identity), now).expect("compile filters");
        assert_eq!(table, "incident");
        assert_eq!(
            eq.build(),
            "assigned_to=6816f79cc0a8016401c5a33be04be441^assignment_groupIN11111111111111111111111111111111,22222222222222222222222222222222^active=true^priorityIN1,2^sys_updated_on>=2026-10-22 14:00:00^ORDERBYDESCsys_updated_on"
        );
    }
}
