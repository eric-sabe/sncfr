use crate::cache::InstanceCache;
use crate::config::{AppConfig, ResolvedProfile};
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;
use crate::resolve::builtin_prefixes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillInstallSummary {
    pub path: String,
    pub profile: Option<String>,
    pub bytes_written: usize,
}

/// Generates an instance-aware `SKILL.md` document for AI coding and operations agents.
pub fn generate_skill_markdown(config: &AppConfig, profile: Option<&ResolvedProfile>) -> String {
    let mut md = String::new();
    md.push_str(
        "---\n\
name: sncfr\n\
description: Explore, monitor, and act on ServiceNow tickets (INC, RITM, SCTASK, CHG, PRB, REQ, CS) using the read-only-by-default `sncfr` CLI. Use whenever the user references a ServiceNow ticket number, ServiceNow URL, queue/triage view, incident, change request, catalog request, or approval.\n\
---\n\n\
# `sncfr` — ServiceNow CLI Skill for AI Agents\n\n\
`sncfr` (\"ServiceNow CLI, For Real\") is an agent-friendly, read-only-by-default ServiceNow CLI for non-admin users.\n\n",
    );

    // 1. Instance & Profile Context (if available)
    if let Some(prof) = profile {
        md.push_str("## Active Instance & Profile Context\n\n");
        md.push_str(&format!(
            "- **Profile**: `{}` (`{}`)\n",
            prof.name,
            prof.instance_url.as_str().trim_end_matches('/')
        ));
        md.push_str(&format!(
            "- **Safety Lock**: {}\n",
            if prof.is_read_only_locked() {
                "Hard Read-Only Locked (`--write` is disabled on this profile)"
            } else {
                "Read-Only by default; pass `--write` only when explicitly instructed to commit a change"
            }
        ));

        if let Ok(cache) = InstanceCache::for_instance(&prof.instance_key) {
            if let Ok(Some(id)) = cache.read_identity() {
                let groups: Vec<&str> = id.groups.iter().map(|g| g.name.as_str()).collect();
                md.push_str(&format!(
                    "- **Authenticated User (`@me`)**: {} (`{}`)\n",
                    id.display_name, id.user_name
                ));
                if !groups.is_empty() {
                    md.push_str(&format!(
                        "- **Assignment Groups (`@my-groups`)**: {}\n",
                        groups.join(", ")
                    ));
                }
            }

            let mut prefixes = builtin_prefixes();
            if let Ok(Some(cached_p)) = cache.read_prefixes() {
                for (k, v) in cached_p.prefixes {
                    prefixes.insert(k, v);
                }
            }
            let prefix_list: Vec<String> = prefixes
                .iter()
                .map(|(k, v)| format!("`{k}*` -> `{v}`"))
                .collect();
            md.push_str(&format!(
                "- **Known Ticket Prefixes**: {}\n",
                prefix_list.join(", ")
            ));
        }
        md.push('\n');

        if !prof.views.is_empty() {
            md.push_str("### Configured Saved Views (`@<view>`)\n\n");
            md.push_str("| View | Table | Query | Usage |\n");
            md.push_str("| :--- | :--- | :--- | :--- |\n");
            for (view_name, view) in &prof.views {
                md.push_str(&format!(
                    "| `@{view_name}` | `{}` | `{}` | `sncfr list @{view_name}` / `sncfr feed @{view_name}` |\n",
                    view.table, view.query
                ));
            }
            md.push('\n');
        }
    } else if !config.profiles.is_empty() {
        md.push_str("## Configured Profiles\n\n");
        for (name, p) in &config.profiles {
            md.push_str(&format!(
                "- **`{name}`**: `{}` (read_only: `{}`)\n",
                p.instance, p.read_only
            ));
        }
        md.push('\n');
    }

    // 2. Non-Negotiable Safety Rules for Agents
    md.push_str(
        "## Mandatory Safety Rules for Agents\n\n\
1. **Read-Only by Default**: Every exploration command (`show`, `list`, `search`, `feed`, `stats`, `attachments`, `schema`, `table`, `doctor`) is 100% read-only.\n\
2. **Always Run Validated Dry-Run Before `--write`**:\n\
   - Mutating commands (`comment`, `note`, `update`, `create`, `attach`, `approvals approve/reject`, `catalog order`) run as a **Validated Dry-Run Preview** when called **without** `--write`.\n\
   - Always run the command without `--write` first to validate choice labels (`state`, `priority`, `close_code`) and user/group references against the live instance and inspect the `Before -> After` diff.\n\
   - Only pass `--write` when the user has explicitly authorized modifying the ticket.\n\
3. **`comment` vs. `note`**:\n\
   - `sncfr comment <TICKET> \"...\"` posts a **customer-visible** comment (`comments`).\n\
   - `sncfr note <TICKET> \"...\"` posts an **internal fulfiller work note** (`work_notes`).\n\
   - Never post internal diagnostics or sensitive notes via `comment`; prefer `note` unless the user asks to reply to the customer.\n\n",
    );

    // 3. Core Command Cookbook
    md.push_str(
        "## Command Quick Reference\n\n\
### 1. Inspect a Ticket Dossier (Single `/api/now/batch` Round-Trip)\n\
```bash\n\
# Returns curated core fields, non-empty u_*/x_* custom fields, catalog variables, activity stream, related tasks, and attachments:\n\
sncfr show INC0010042\n\
sncfr show RITM0049210 SCTASK0019283\n\
```\n\n\
### 2. List, Search, & Monitor Ticket Queues\n\
```bash\n\
# List tickets assigned to or opened by @me:\n\
sncfr list --mine --active\n\n\
# List tickets in @my-groups or a saved view:\n\
sncfr list --group @my-groups --active --priority 1,2\n\
sncfr list @team-triage\n\n\
# Parse any pasted ServiceNow browser URL directly into a structured list:\n\
sncfr list --from-url \"https://instance.service-now.com/now/nav/ui/classic/params/target/incident_list.do%3Fsysparm_query%3Dactive%3Dtrue\"\n\n\
# Full-text search combined with filters:\n\
sncfr search \"VPN gateway timeout\" --table inc --updated-since 7d\n\n\
# Activity feed / delta monitor across a queue (new comments, work notes, state changes):\n\
sncfr feed --group @my-groups --since 4h\n\n\
# Instant queue counts via Aggregate API (/api/now/stats):\n\
sncfr stats --group @my-groups --active --by state\n\
sncfr stats --mine --active --by priority\n\
```\n\n\
### 3. Inspect Schema & Valid `sys_choice` Values\n\
```bash\n\
sncfr schema inc --choices state\n\
sncfr schema chg --choices\n\
```\n\n\
### 4. Validated Dry-Run Previews & Ticket Mutations (`--write`)\n\
```bash\n\
# Step 1: Run Validated Dry-Run Preview (no --write):\n\
sncfr update INC0010042 --state \"In Progress\" --assign-to @me --note \"Investigating root cause\"\n\n\
# Step 2: Commit with --write once verified:\n\
sncfr update INC0010042 --state \"In Progress\" --assign-to @me --note \"Investigating root cause\" --write\n\n\
# Post an internal work note vs. customer-visible comment:\n\
sncfr note INC0010042 \"Confirmed TLS cert rotation completed\" --write\n\
sncfr comment INC0010042 \"This issue has been resolved; please verify.\" --write\n\
```\n\n\
### 5. Approvals, Service Catalog, & Attachments\n\
```bash\n\
# List and approve pending approvals:\n\
sncfr approvals list\n\
sncfr approvals approve CHG0031002 --comments \"LGTM\" --write\n\n\
# Browse and order Service Catalog items:\n\
sncfr catalog search \"AWS Sandbox\"\n\
sncfr catalog show <item_sys_id>\n\
sncfr catalog order <item_sys_id> --var aws_region=us-east-1\n\n\
# List and download ticket attachments:\n\
sncfr attachments INC0010042 --download --out-dir ./tmp-attachments\n\
```\n\n\
## Exit Codes & Error Handling\n\n\
- `0`: Success (`OK` or `DRY_RUN_OK`).\n\
- `2`: `INVALID_ARGS` / `VALIDATION_ERROR` (inspect `valid_choices` in the JSON error output).\n\
- `3`: `AUTH_EXPIRED` / `AUTH_REQUIRED` (instruct the user to run `sncfr auth login`).\n\
- `4`: `ACL_FORBIDDEN` (run `sncfr doctor` to inspect non-admin table permissions).\n\
- `5`: `NOT_FOUND`.\n\
- `6`: `READ_ONLY_LOCKED` (`SNCFR_READ_ONLY` or profile `read_only = true` is active).\n\
- `7`: `NETWORK_OR_INSTANCE_ERROR`.\n",
    );

    md
}

/// Writes the generated `SKILL.md` to `dest_path`, creating parent directories as needed.
pub fn install_skill_markdown(
    dest_path: &Path,
    config: &AppConfig,
    profile: Option<&ResolvedProfile>,
) -> Result<SkillInstallSummary, SncfrError> {
    let md = generate_skill_markdown(config, profile);
    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| SncfrError::InvalidArgs {
            message: format!(
                "Failed to create skill directory '{}': {e}",
                parent.display()
            ),
            remediation: None,
        })?;
    }
    fs::write(dest_path, &md).map_err(|e| SncfrError::InvalidArgs {
        message: format!("Failed to write SKILL.md to '{}': {e}", dest_path.display()),
        remediation: None,
    })?;

    Ok(SkillInstallSummary {
        path: dest_path.display().to_string(),
        profile: profile.map(|p| p.name.clone()),
        bytes_written: md.len(),
    })
}

pub fn format_skill_install(summary: &SkillInstallSummary, format: ResolvedOutputFormat) -> String {
    match format {
        ResolvedOutputFormat::Json => serde_json::to_string_pretty(summary).unwrap_or_default(),
        ResolvedOutputFormat::Yaml => serde_yaml::to_string(summary).unwrap_or_default(),
        _ => format!(
            "Installed sncfr agent skill to '{}' ({} bytes).",
            summary.path, summary.bytes_written
        ),
    }
}
