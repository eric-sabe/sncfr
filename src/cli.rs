use crate::output::{CommandOutputShape, OutputFormat};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// `sncfr` ("ServiceNow CLI, For Real") — Agent-friendly, read-only-by-default ServiceNow CLI.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "sncfr",
    version,
    about = "Agent-friendly, read-only-by-default ServiceNow CLI for non-admin users",
    propagate_version = true
)]
pub struct Cli {
    /// Named connection profile from `~/.config/sncfr/config.toml`
    #[arg(short, long, global = true, env = "SNCFR_PROFILE")]
    pub profile: Option<String>,

    /// Target ServiceNow instance URL or hostname (overrides profile instance)
    #[arg(long, global = true, env = "SNCFR_INSTANCE")]
    pub instance: Option<String>,

    /// Output format (`auto` detects TTY vs. piped/agent execution)
    #[arg(
        short,
        long,
        global = true,
        env = "SNCFR_OUTPUT",
        value_enum,
        default_value_t = OutputFormat::Auto
    )]
    pub output: OutputFormat,

    /// Shorthand for `--output json`
    #[arg(long, global = true)]
    pub json: bool,

    /// Never prompt or auto-launch interactive SSO browser windows
    #[arg(long, global = true)]
    pub no_interactive: bool,

    /// Enforce hard read-only lock for this invocation (rejects `--write` with exit code 6)
    #[arg(
        long,
        global = true,
        env = "SNCFR_READ_ONLY",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub read_only: bool,

    /// Enable verbose diagnostic logging to stderr
    #[arg(
        short,
        long,
        global = true,
        env = "SNCFR_VERBOSE",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub verbose: bool,

    /// Write detailed debug logs to a file (appends timestamped trace lines)
    #[arg(long, global = true, env = "SNCFR_LOG_FILE")]
    pub log_file: Option<PathBuf>,

    /// Instance Pack layered over the profile's `pack =` for this invocation (ADR-0004)
    #[arg(long, global = true, env = "SNCFR_PACK")]
    pub pack: Option<PathBuf>,

    /// Per-request timeout in seconds (1-300; default 30, or profile `timeout_secs`)
    #[arg(long, global = true, env = "SNCFR_TIMEOUT", value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Send these UNVERIFIABLE fields exactly as typed (explicit names only; catalog variables
    /// as `var:<name>`). Only on explicit user instruction (SAFE-4)
    #[arg(long, global = true, value_delimiter = ',', value_name = "FIELD,...")]
    pub allow_unverified: Vec<String>,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Returns the effective [`OutputFormat`], respecting the `--json` shorthand.
    pub const fn effective_output(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.output
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Assemble a complete Ticket Dossier (fields, custom `u_*`/`x_*` fields, catalog variables, activity stream, hierarchy, attachments)
    #[command(visible_aliases = ["view", "get"])]
    Show(ShowArgs),

    /// List tickets matching ergonomic filters, a saved view (`@view`), or a ServiceNow URL
    #[command(visible_alias = "ls")]
    List(ListArgs),

    /// Full-text search across tickets, combinable with list filters
    Search(SearchArgs),

    /// Activity feed / delta monitor showing recent comments, work notes, and state changes across tickets
    Feed(FeedArgs),

    /// Instant queue aggregations via the ServiceNow Aggregate API (`/api/now/stats`)
    Stats(StatsArgs),

    /// List or download file attachments for a ticket
    Attachments(AttachmentsArgs),

    /// Post a customer-visible comment (`comments` field). Runs as Validated Dry-Run unless `--write` is passed.
    Comment(CommentArgs),

    /// Post an internal fulfiller work note (`work_notes` field). Runs as Validated Dry-Run unless `--write` is passed.
    Note(NoteArgs),

    /// Update ticket fields, state, or assignment. Runs as Validated Dry-Run unless `--write` is passed.
    Update(UpdateArgs),

    /// Create a new ticket record. Runs as Validated Dry-Run unless `--write` is passed.
    Create(CreateArgs),

    /// Upload one or more file attachments to a ticket. Runs as Validated Dry-Run unless `--write` is passed.
    Attach(AttachArgs),

    /// Manage Corporate SSO authentication, session import, and instance profiles
    #[command(subcommand)]
    Auth(AuthCommands),

    /// Inspect pending approvals (`sysapproval_approver`) and approve/reject with `--write`
    #[command(subcommand)]
    Approvals(ApprovalCommands),

    /// Browse Service Catalog items, inspect variables, and submit orders with `--write`
    #[command(subcommand)]
    Catalog(CatalogCommands),

    /// Inspect table schema, custom fields (`u_*`/`x_*`), and valid `sys_choice` options
    Schema(SchemaArgs),

    /// Look up configuration items (read-only, WF-1)
    #[command(subcommand)]
    Cmdb(CmdbCommands),

    /// Read-only query escape hatch for arbitrary ServiceNow tables (`sys_user`, `cmdb_ci`, `kb_knowledge`, etc.)
    Table(TableArgs),

    /// Generate or install an instance-aware `SKILL.md` guide for AI coding agents
    #[command(subcommand)]
    Skill(SkillCommands),

    /// Run connectivity, TLS, Corporate SSO session, and non-admin ACL capability diagnostics
    Doctor(DoctorArgs),

    /// Probe the instance (read-only) and write a draft Instance Pack (DISC-4, DISC-5)
    Discover(DiscoverArgs),

    /// Validate or inspect Instance Packs (ADR-0004)
    #[command(subcommand)]
    Pack(PackCommands),
}

#[derive(Debug, Clone, Default, Args)]
pub struct DoctorArgs {
    /// Forget the capability record and re-probe every capability (CAP-2, CAP-6)
    #[arg(long)]
    pub refresh: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DiscoverArgs {
    /// Where to write the draft (default: `<config dir>/packs/<instance-host>.draft.pack.toml`)
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
    /// Read no record rows: skip task-row prefix sampling, the custom field inventory, and group
    /// suffix detection (prefixes then come from `sys_number` only)
    #[arg(long)]
    pub no_samples: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum PackCommands {
    /// Check a pack file: schema, types, references between sections, duplicate prefixes/aliases
    Validate {
        /// Path to the pack TOML file
        path: PathBuf,
    },
    /// Print the merged pack (ootb + profile pack + `--pack`) with per-entry origins and its hash
    Show {
        /// Emit the merged pack as re-loadable TOML instead of the summary
        #[arg(long)]
        toml: bool,
    },
}

impl Commands {
    /// Returns the [`CommandOutputShape`] used when resolving [`OutputFormat::Auto`].
    pub const fn output_shape(&self) -> CommandOutputShape {
        match self {
            Self::Show(_)
            | Self::Feed(_)
            | Self::Comment(_)
            | Self::Note(_)
            | Self::Update(_)
            | Self::Create(_)
            | Self::Attach(_)
            | Self::Skill(_)
            | Self::Pack(_)
            | Self::Doctor(_)
            | Self::Discover(_) => CommandOutputShape::Dossier,
            Self::List(_)
            | Self::Search(_)
            | Self::Stats(_)
            | Self::Attachments(_)
            | Self::Auth(_)
            | Self::Approvals(_)
            | Self::Catalog(_)
            | Self::Cmdb(_)
            | Self::Schema(_)
            | Self::Table(_) => CommandOutputShape::Tabular,
        }
    }

    /// Returns `true` if the subcommand is a mutating command where `--write` was explicitly requested.
    pub const fn requests_write(&self) -> bool {
        match self {
            Self::Comment(args) | Self::Note(args) => args.write,
            Self::Update(args) => args.write,
            Self::Create(args) => args.write,
            Self::Attach(args) => args.write,
            Self::Approvals(ApprovalCommands::Approve(args) | ApprovalCommands::Reject(args)) => {
                args.write
            }
            Self::Catalog(CatalogCommands::Order(args)) => args.write,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct ShowArgs {
    /// One or more ticket numbers (e.g., `INC0010042`, `RITM0049210`, `CHG0031002`)
    #[arg(required = true, num_args = 1..)]
    pub tickets: Vec<String>,

    /// Include all raw fields (including empty and internal `sys_*` columns)
    #[arg(long)]
    pub all_fields: bool,

    /// Comma-separated list of specific fields to include
    #[arg(long, value_delimiter = ',')]
    pub fields: Vec<String>,

    /// Skip fetching journal entries (`comments` and `work_notes`)
    #[arg(long)]
    pub no_journal: bool,

    /// Skip fetching related tasks, approvals, and configuration items
    #[arg(long)]
    pub no_related: bool,
}

/// Shared filter flags across `list`, `search`, `feed`, `stats`, and `table`.
#[derive(Debug, Clone, Default, Args)]
pub struct ListFilterArgs {
    /// Target table name or ticket prefix (e.g., `incident`, `inc`, `sc_req_item`, `ritm`, `task`)
    #[arg(short, long)]
    pub table: Option<String>,

    /// Tickets assigned to, opened by, or requested for `@me`
    #[arg(long)]
    pub mine: bool,

    /// Filter by assigned user (`@me`, `unassigned`, username, email, or `sys_id`)
    #[arg(long)]
    pub assigned_to: Option<String>,

    /// Filter by opener (`@me`, username, email, or `sys_id`)
    #[arg(long)]
    pub opened_by: Option<String>,

    /// Filter by assignment group (`@my-groups`, group name, or `sys_id`); names expand through
    /// the Instance Pack's group suffixes
    #[arg(short, long, visible_aliases = ["assignment-group"])]
    pub group: Option<String>,

    /// Filter by watch list member (`@me`, username, or `sys_id`)
    #[arg(long)]
    pub watch_list: Option<String>,

    /// Only include active tickets (`active=true`)
    #[arg(long, conflicts_with = "inactive")]
    pub active: bool,

    /// Only include inactive/closed tickets (`active=false`)
    #[arg(long, conflicts_with = "active")]
    pub inactive: bool,

    /// Only open tickets: the Instance Pack's `open_rule.<table>` where defined, else `active=true`
    #[arg(long, conflicts_with_all = ["active", "inactive", "closed"])]
    pub open: bool,

    /// Only closed tickets: the pack's `closed_rule.<table>` where defined, else `active=false`
    #[arg(long, conflicts_with_all = ["active", "inactive", "open"])]
    pub closed: bool,

    /// Filter by one or more state labels or codes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub state: Vec<String>,

    /// Filter by one or more priority levels (e.g., `1,2`)
    #[arg(long, value_delimiter = ',')]
    pub priority: Vec<String>,

    /// Only tickets updated within relative duration or since ISO timestamp (e.g., `4h`, `2d`, `2026-10-20`)
    #[arg(long)]
    pub updated_since: Option<String>,

    /// Only tickets created within relative duration or since ISO timestamp (e.g., `24h`, `7d`)
    #[arg(long)]
    pub created_since: Option<String>,

    /// Parse table and `sysparm_query` directly from a pasted ServiceNow UI URL
    #[arg(long)]
    pub from_url: Option<String>,

    /// Raw ServiceNow encoded query (`sysparm_query`)
    #[arg(short, long)]
    pub query: Option<String>,

    /// Comma-separated list of fields to return
    #[arg(long, value_delimiter = ',')]
    pub fields: Vec<String>,

    /// Maximum number of records to return
    #[arg(short, long, default_value_t = 25)]
    pub limit: u32,

    /// Starting record offset for pagination
    #[arg(long, default_value_t = 0)]
    pub offset: u32,

    /// Also return the total number of matching records (asks the instance to count, which can be
    /// slow on very large tables; `stats` is the cheaper count path)
    #[arg(long)]
    pub with_count: bool,

    /// Field name to sort by (default: `sys_updated_on`)
    #[arg(long)]
    pub sort: Option<String>,

    /// Sort in ascending order
    #[arg(long, conflicts_with = "desc")]
    pub asc: bool,

    /// Sort in descending order (default when `--sort` is used)
    #[arg(long, conflicts_with = "asc")]
    pub desc: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Optional saved view name prefixed with `@` (e.g., `@my-active`, `@team-triage`)
    pub view: Option<String>,

    #[command(flatten)]
    pub filters: ListFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct SearchArgs {
    /// Search phrase or keywords
    pub text: String,

    #[command(flatten)]
    pub filters: ListFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct FeedArgs {
    /// Optional saved view name prefixed with `@` (e.g., `@team-triage`)
    pub view: Option<String>,

    /// Relative lookback window or ISO timestamp (default: `4h`)
    #[arg(long, default_value = "4h")]
    pub since: String,

    #[command(flatten)]
    pub filters: ListFilterArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum StatsGroupBy {
    State,
    Priority,
    AssignmentGroup,
    AssignedTo,
    SysClassName,
    Category,
}

impl StatsGroupBy {
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Priority => "priority",
            Self::AssignmentGroup => "assignment_group",
            Self::AssignedTo => "assigned_to",
            Self::SysClassName => "sys_class_name",
            Self::Category => "category",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct StatsArgs {
    /// Optional saved view name prefixed with `@`
    pub view: Option<String>,

    /// Field to group counts by
    #[arg(long, value_enum, default_value_t = StatsGroupBy::State)]
    pub by: StatsGroupBy,

    #[command(flatten)]
    pub filters: ListFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct AttachmentsArgs {
    /// Target ticket number (e.g., `INC0010042`)
    pub ticket: String,

    /// Download attachments locally (pass a specific filename/`sys_id` or omit value to download all)
    #[arg(long, num_args = 0..=1, default_missing_value = "*")]
    pub download: Option<String>,

    /// Output directory for downloaded attachments (default: current directory)
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
}

/// Shared args for `comment` and `note`.
#[derive(Debug, Clone, Args)]
pub struct CommentArgs {
    /// Target ticket number (e.g., `INC0010042`)
    pub ticket: String,

    /// Comment or work note body text (required unless `--file` is provided)
    #[arg(required_unless_present = "file")]
    pub message: Option<String>,

    /// Read comment/note body from a file path
    #[arg(short, long)]
    pub file: Option<PathBuf>,

    /// Execute the mutation against ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,

    /// Permit `[code]` in the body (rendered as HTML by ServiceNow); a warning is still printed
    #[arg(long)]
    pub allow_code_tag: bool,
}

pub type NoteArgs = CommentArgs;

#[derive(Debug, Clone, Args)]
pub struct UpdateArgs {
    /// Target ticket number (e.g., `INC0010042`)
    pub ticket: String,

    /// Set ticket state label or code (e.g., `"In Progress"`, `"Resolved"`)
    #[arg(long)]
    pub state: Option<String>,

    /// Set ticket priority label or code
    #[arg(long)]
    pub priority: Option<String>,

    /// Set ticket urgency label or code
    #[arg(long)]
    pub urgency: Option<String>,

    /// Set ticket impact label or code
    #[arg(long)]
    pub impact: Option<String>,

    /// Assign ticket to user (`@me`, `none`, username, email, or `sys_id`)
    #[arg(long)]
    pub assign_to: Option<String>,

    /// Assign ticket to assignment group (group name or `sys_id`)
    #[arg(long, visible_aliases = ["assignment-group", "assign-to-group"])]
    pub group: Option<String>,

    /// Update `short_description`
    #[arg(long)]
    pub short_description: Option<String>,

    /// Update `description`
    #[arg(long)]
    pub description: Option<String>,

    /// Set resolution/close code (`close_code`)
    #[arg(long)]
    pub close_code: Option<String>,

    /// Set resolution/close notes (`close_notes`)
    #[arg(long)]
    pub close_notes: Option<String>,

    /// Include an internal work note (`work_notes`) with this update
    #[arg(long)]
    pub note: Option<String>,

    /// Include a customer-visible comment (`comments`) with this update
    #[arg(long)]
    pub comment: Option<String>,

    /// Set arbitrary field=value pairs (repeatable, e.g., `--set u_environment=prod`)
    #[arg(long = "set", value_name = "FIELD=VALUE")]
    pub set_fields: Vec<String>,

    /// Execute the mutation against ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,

    /// Permit `[code]` in `--note` / `--comment` (rendered as HTML by ServiceNow)
    #[arg(long)]
    pub allow_code_tag: bool,
}

#[derive(Debug, Clone, Args)]
pub struct CreateArgs {
    /// Target table name or prefix (e.g., `incident`, `inc`, `change_request`, `chg`)
    pub table_or_prefix: String,

    /// Ticket `short_description` (required)
    #[arg(long)]
    pub short_description: String,

    /// Detailed `description`
    #[arg(long)]
    pub description: Option<String>,

    /// Priority label or code
    #[arg(long)]
    pub priority: Option<String>,

    /// Urgency label or code
    #[arg(long)]
    pub urgency: Option<String>,

    /// Impact label or code
    #[arg(long)]
    pub impact: Option<String>,

    /// Assignee (`@me`, username, email, or `sys_id`)
    #[arg(long)]
    pub assign_to: Option<String>,

    /// Assignment group (group name or `sys_id`)
    #[arg(long, visible_aliases = ["assignment-group", "assign-to-group"])]
    pub group: Option<String>,

    /// Caller / requested-for user (`@me`, username, email, or `sys_id`)
    #[arg(long)]
    pub caller: Option<String>,

    /// Set arbitrary field=value pairs (repeatable, e.g., `--set category=network`)
    #[arg(long = "set", value_name = "FIELD=VALUE")]
    pub set_fields: Vec<String>,

    /// Execute the mutation against ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AttachArgs {
    /// Target ticket number (e.g., `INC0010042`)
    pub ticket: String,

    /// One or more local file paths to attach
    #[arg(required = true, num_args = 1..)]
    pub files: Vec<PathBuf>,

    /// Execute the upload against ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum AuthCommands {
    /// Launch an isolated managed browser `--app` window via CDP to complete Corporate SSO and store session in OS Keychain
    Login(AuthLoginArgs),

    /// Verify active session status and display `@me` user and group identity
    Status,

    /// Import session credentials from a pasted DevTools "Copy as cURL" command or raw Cookie/X-UserToken headers
    Import(AuthImportArgs),

    /// Clear cached session credentials from the OS Keychain
    Logout,

    /// List configured connection profiles from `config.toml`
    Profiles,
}

#[derive(Debug, Clone, Args)]
pub struct AuthLoginArgs {
    /// Explicit path to Chromium/Chrome/Edge/Brave executable
    #[arg(long)]
    pub browser: Option<PathBuf>,

    /// Timeout in seconds waiting for interactive SSO completion
    #[arg(long, default_value_t = 180)]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Args)]
pub struct AuthImportArgs {
    /// Read "Copy as cURL" or raw headers from file (reads from stdin if omitted and `--cookie` is not set)
    #[arg(short, long)]
    pub file: Option<PathBuf>,

    /// Explicit `Cookie` header string
    #[arg(long)]
    pub cookie: Option<String>,

    /// Explicit `X-UserToken` (`g_ck`) token value
    #[arg(long)]
    pub user_token: Option<String>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ApprovalCommands {
    /// List pending approvals (`sysapproval_approver`) for `@me`
    List(ApprovalListArgs),

    /// Show details of a specific approval record and its target ticket
    Show {
        /// Approval `sys_id` or target ticket number
        approval_or_ticket: String,
    },

    /// Approve a pending approval record (runs Dry-Run unless `--write` is passed)
    Approve(ApprovalActionArgs),

    /// Reject a pending approval record (runs Dry-Run unless `--write` is passed)
    Reject(ApprovalActionArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ApprovalListArgs {
    /// Approval state filter (default: `requested`)
    #[arg(long, default_value = "requested")]
    pub state: String,

    /// Include approvals assigned to any user (instead of only `@me`)
    #[arg(long)]
    pub all_users: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ApprovalActionArgs {
    /// Approval `sys_id` or target ticket number
    pub approval_or_ticket: String,

    /// Approval/rejection comments
    #[arg(short, long)]
    pub comments: Option<String>,

    /// Execute the approval/rejection in ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CmdbCommands {
    /// Find a CI by hostname, IP, FQDN, serial number, or sys_id, with its support group,
    /// relationships, and open tasks
    Lookup {
        /// Hostname, IPv4/IPv6 address, FQDN, serial number, or 32-hex sys_id
        input: String,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum CatalogCommands {
    /// Search available Service Catalog items (`/api/sn_sc/servicecatalog/items`)
    Search {
        /// Search query for catalog items
        query: String,

        /// Maximum items to return
        #[arg(short, long, default_value_t = 20)]
        limit: u32,
    },

    /// Show details and required/optional form variables for a Service Catalog item
    Show {
        /// Catalog item `sys_id` or exact name
        item: String,
    },

    /// Submit a Service Catalog item request (runs Dry-Run unless `--write` is passed)
    Order(CatalogOrderArgs),
}

#[derive(Debug, Clone, Args)]
pub struct CatalogOrderArgs {
    /// Catalog item `sys_id`
    pub item_sys_id: String,

    /// Variable key=value pairs (`--var key=value`)
    #[arg(long = "var", value_name = "VARIABLE=VALUE")]
    pub variables: Vec<String>,

    /// Quantity to order
    #[arg(long, default_value_t = 1)]
    pub quantity: u32,

    /// Requested-for user (`@me`, username, or `sys_id`)
    #[arg(long)]
    pub requested_for: Option<String>,

    /// Execute the catalog order in ServiceNow (without this flag, runs a Validated Dry-Run Preview)
    #[arg(short, long)]
    pub write: bool,

    /// After `--write`, wait at most this long for the requested items to appear (default: pack
    /// `catalog.poll.max_wait_secs`, else 20)
    #[arg(long, value_name = "SECS")]
    pub poll_timeout: Option<u64>,

    /// After the order, also set the pack's `catalog.post_order_fill.fields` on the requested
    /// item it creates (checked before the order is sent; off by default)
    #[arg(long)]
    pub fill_ritm: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SchemaArgs {
    /// Table name or ticket prefix (e.g., `incident`, `inc`, `change_request`, `chg`)
    pub table_or_prefix: String,

    /// Inspect valid `sys_choice` options (optionally pass a specific field name like `state`)
    #[arg(long, num_args = 0..=1, default_missing_value = "*")]
    pub choices: Option<String>,

    /// Force refresh of cached schema/choice metadata from the instance
    #[arg(long)]
    pub sync: bool,
}

#[derive(Debug, Clone, Args)]
pub struct TableArgs {
    /// Arbitrary ServiceNow table name (e.g., `sys_user`, `sys_user_group`, `cmdb_ci`, `kb_knowledge`)
    pub table_name: String,

    #[command(flatten)]
    pub filters: ListFilterArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SkillCommands {
    /// Print the generated instance-aware `SKILL.md` to stdout
    Print,

    /// Write `SKILL.md` to a target directory (e.g., `.agents/skills/sncfr/SKILL.md`)
    Install {
        /// Destination path for `SKILL.md`
        #[arg(long, default_value = ".agents/skills/sncfr/SKILL.md")]
        path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_show_and_aliases() {
        let cli = Cli::try_parse_from(["sncfr", "show", "INC0010042", "RITM0020001"])
            .expect("parse show");
        match &cli.command {
            Commands::Show(args) => {
                assert_eq!(args.tickets, vec!["INC0010042", "RITM0020001"]);
                assert!(!args.all_fields);
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert_eq!(cli.command.output_shape(), CommandOutputShape::Dossier);
        assert!(!cli.command.requests_write());

        // Verify `view` and `get` aliases
        for alias in ["view", "get"] {
            let aliased =
                Cli::try_parse_from(["sncfr", alias, "CHG0030001"]).expect("parse show alias");
            assert!(matches!(aliased.command, Commands::Show(_)));
        }
    }

    #[test]
    fn parses_list_with_saved_view_and_filters() {
        let cli = Cli::try_parse_from([
            "sncfr",
            "ls",
            "@team-triage",
            "--mine",
            "--active",
            "--priority",
            "1,2",
            "--updated-since",
            "4h",
            "--limit",
            "50",
        ])
        .expect("parse list");

        match &cli.command {
            Commands::List(args) => {
                assert_eq!(args.view.as_deref(), Some("@team-triage"));
                assert!(args.filters.mine);
                assert!(args.filters.active);
                assert_eq!(args.filters.priority, vec!["1", "2"]);
                assert_eq!(args.filters.updated_since.as_deref(), Some("4h"));
                assert_eq!(args.filters.limit, 50);
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert_eq!(cli.command.output_shape(), CommandOutputShape::Tabular);
    }

    #[test]
    fn mutating_commands_default_to_dry_run_and_detect_write_flag() {
        let dry_run = Cli::try_parse_from([
            "sncfr",
            "update",
            "INC0010042",
            "--state",
            "In Progress",
            "--assign-to",
            "@me",
        ])
        .expect("parse update dry-run");
        assert!(!dry_run.command.requests_write());

        let with_write = Cli::try_parse_from([
            "sncfr",
            "update",
            "INC0010042",
            "--state",
            "In Progress",
            "--write",
        ])
        .expect("parse update --write");
        assert!(with_write.command.requests_write());
    }

    #[test]
    fn parses_feed_stats_attachments_and_specialized_namespaces() {
        let feed = Cli::try_parse_from(["sncfr", "feed", "@my-active", "--since", "2h"])
            .expect("parse feed");
        assert!(matches!(feed.command, Commands::Feed(_)));
        assert_eq!(feed.command.output_shape(), CommandOutputShape::Dossier);

        let stats = Cli::try_parse_from(["sncfr", "stats", "--by", "assignment_group", "--active"])
            .expect("parse stats");
        match &stats.command {
            Commands::Stats(args) => {
                assert_eq!(args.by, StatsGroupBy::AssignmentGroup);
                assert_eq!(args.by.field_name(), "assignment_group");
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert_eq!(stats.command.output_shape(), CommandOutputShape::Tabular);

        let attach_dl = Cli::try_parse_from(["sncfr", "attachments", "INC0010042", "--download"])
            .expect("parse attachments --download");
        match attach_dl.command {
            Commands::Attachments(args) => {
                assert_eq!(args.download.as_deref(), Some("*"));
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let schema =
            Cli::try_parse_from(["sncfr", "schema", "inc", "--choices", "state", "--sync"])
                .expect("parse schema");
        match schema.command {
            Commands::Schema(args) => {
                assert_eq!(args.table_or_prefix, "inc");
                assert_eq!(args.choices.as_deref(), Some("state"));
                assert!(args.sync);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
