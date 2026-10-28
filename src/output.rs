use crate::error::SncfrError;
use clap::ValueEnum;
use comfy_table::{Attribute, Cell, Color};
use owo_colors::OwoColorize;
use serde::Serialize;
use std::io::IsTerminal;

/// User-configurable `--output` / `-o` mode per `docs/SPEC.md` Section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Auto-detect based on whether `stdout` is an interactive TTY and the command shape.
    #[default]
    Auto,
    /// Token-compact GitHub-Flavored Markdown.
    Md,
    /// Deterministic, pruned JSON with envelope metadata.
    Json,
    /// YAML representation of the pruned JSON structure.
    Yaml,
    /// Aligned terminal table.
    Table,
}

/// Classification of a command's primary output shape when resolving [`OutputFormat::Auto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutputShape {
    /// Rich multi-section narrative/dossier (`show`, `feed`, dry-run previews, `doctor`, `skill`).
    /// Auto resolves to `TerminalDossier` on TTY and `Md` when piped.
    Dossier,
    /// Structured list, queue, or aggregation (`list`, `search`, `stats`, `table`, `schema`, `approvals`, `catalog`).
    /// Auto resolves to `Table` on TTY and `Json` when piped.
    Tabular,
}

/// Concrete resolved output format after evaluating `OutputFormat` against TTY state and command shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedOutputFormat {
    /// Rich terminal layout with ANSI styling and OSC 8 hyperlinks.
    TerminalDossier,
    /// Aligned terminal table.
    Table,
    /// GitHub-Flavored Markdown.
    Md,
    /// Pruned JSON.
    Json,
    /// Pruned YAML.
    Yaml,
}

impl OutputFormat {
    /// Resolves the concrete output format using current `stdout` TTY detection.
    pub fn resolve(self, shape: CommandOutputShape) -> ResolvedOutputFormat {
        self.resolve_with_tty(shape, std::io::stdout().is_terminal())
    }

    /// Resolves the concrete output format for an explicit `is_tty` boolean (used in tests and runtime).
    pub const fn resolve_with_tty(
        self,
        shape: CommandOutputShape,
        is_tty: bool,
    ) -> ResolvedOutputFormat {
        match self {
            Self::Auto => match (is_tty, shape) {
                (true, CommandOutputShape::Dossier) => ResolvedOutputFormat::TerminalDossier,
                (true, CommandOutputShape::Tabular) => ResolvedOutputFormat::Table,
                (false, CommandOutputShape::Dossier) => ResolvedOutputFormat::Md,
                (false, CommandOutputShape::Tabular) => ResolvedOutputFormat::Json,
            },
            Self::Md => ResolvedOutputFormat::Md,
            Self::Json => ResolvedOutputFormat::Json,
            Self::Yaml => ResolvedOutputFormat::Yaml,
            Self::Table => ResolvedOutputFormat::Table,
        }
    }
}

/// Formats a [`SncfrError`] according to the requested [`OutputFormat`] and whether `stderr` is a TTY.
pub fn format_error(err: &SncfrError, output: OutputFormat, is_tty: bool) -> String {
    match output {
        OutputFormat::Json => serde_json::to_string_pretty(&err.to_envelope())
            .unwrap_or_else(|_| format!("{{\"error\":{{\"message\":\"{err}\"}}}}")),
        OutputFormat::Yaml => serde_yaml::to_string(&err.to_envelope())
            .unwrap_or_else(|_| format!("error:\n  message: \"{err}\"\n")),
        OutputFormat::Auto if !is_tty => serde_json::to_string_pretty(&err.to_envelope())
            .unwrap_or_else(|_| format!("{{\"error\":{{\"message\":\"{err}\"}}}}")),
        _ => {
            let mut out = if is_tty {
                format!(
                    "{} [{}]: {}",
                    "error".red().bold(),
                    err.code().as_str().yellow(),
                    err
                )
            } else {
                format!("error [{}]: {}", err.code().as_str(), err)
            };

            if let SncfrError::Validation { valid_choices, .. } = err
                && !valid_choices.is_empty()
            {
                out.push_str(&format!("\n  valid choices: {}", valid_choices.join(", ")));
            }

            if let Some(remediation) = err.remediation() {
                if is_tty {
                    out.push_str(&format!("\n  {}: {}", "hint".cyan().bold(), remediation));
                } else {
                    out.push_str(&format!("\n  hint: {remediation}"));
                }
            }
            out
        }
    }
}

/// Formats `text` as a clickable OSC 8 terminal hyperlink to `url` (`docs/SPEC.md` Section 6.2).
pub fn osc8_link(url: &str, text: &str) -> String {
    if url.trim().is_empty() || text.trim().is_empty() {
        return text.to_string();
    }
    format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
}

/// Returns a [`comfy_table::Cell`] with status/priority color-coding for terminal tables (`docs/SPEC.md` Section 6.2).
pub fn styled_table_cell(column: &str, value: &str) -> Cell {
    let col_lower = column.to_ascii_lowercase();
    let val_lower = value.to_ascii_lowercase();

    if matches!(
        col_lower.as_str(),
        "state" | "incident_state" | "stage" | "approval"
    ) {
        if val_lower.contains("resolved")
            || val_lower.contains("closed")
            || val_lower.contains("complete")
            || val_lower.contains("approved")
        {
            return Cell::new(value).fg(Color::Green);
        }
        if val_lower.contains("progress")
            || val_lower.contains("open")
            || val_lower.contains("active")
            || val_lower.contains("requested")
        {
            return Cell::new(value).fg(Color::Cyan);
        }
        if val_lower.contains("hold")
            || val_lower.contains("pending")
            || val_lower.contains("awaiting")
        {
            return Cell::new(value).fg(Color::Yellow);
        }
        if val_lower.contains("cancel")
            || val_lower.contains("reject")
            || val_lower.contains("fail")
        {
            return Cell::new(value).fg(Color::Red);
        }
        if val_lower == "new" {
            return Cell::new(value)
                .fg(Color::Blue)
                .add_attribute(Attribute::Bold);
        }
    } else if matches!(col_lower.as_str(), "priority" | "severity" | "urgency") {
        if val_lower.starts_with('1') || val_lower.contains("critical") {
            return Cell::new(value)
                .fg(Color::Red)
                .add_attribute(Attribute::Bold);
        }
        if val_lower.starts_with('2') || val_lower.contains("high") {
            return Cell::new(value)
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold);
        }
        if val_lower.starts_with('3')
            || val_lower.contains("moderate")
            || val_lower.contains("medium")
        {
            return Cell::new(value).fg(Color::Cyan);
        }
    }

    Cell::new(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_output_resolves_per_spec_table_6_1() {
        // Interactive TTY: Dossier -> TerminalDossier, Tabular -> Table
        assert_eq!(
            OutputFormat::Auto.resolve_with_tty(CommandOutputShape::Dossier, true),
            ResolvedOutputFormat::TerminalDossier
        );
        assert_eq!(
            OutputFormat::Auto.resolve_with_tty(CommandOutputShape::Tabular, true),
            ResolvedOutputFormat::Table
        );

        // Piped / Non-TTY (Agent): Dossier -> Md, Tabular -> Json
        assert_eq!(
            OutputFormat::Auto.resolve_with_tty(CommandOutputShape::Dossier, false),
            ResolvedOutputFormat::Md
        );
        assert_eq!(
            OutputFormat::Auto.resolve_with_tty(CommandOutputShape::Tabular, false),
            ResolvedOutputFormat::Json
        );
    }

    #[test]
    fn explicit_output_override_wins_regardless_of_tty() {
        for is_tty in [true, false] {
            for shape in [CommandOutputShape::Dossier, CommandOutputShape::Tabular] {
                assert_eq!(
                    OutputFormat::Md.resolve_with_tty(shape, is_tty),
                    ResolvedOutputFormat::Md
                );
                assert_eq!(
                    OutputFormat::Json.resolve_with_tty(shape, is_tty),
                    ResolvedOutputFormat::Json
                );
                assert_eq!(
                    OutputFormat::Yaml.resolve_with_tty(shape, is_tty),
                    ResolvedOutputFormat::Yaml
                );
                assert_eq!(
                    OutputFormat::Table.resolve_with_tty(shape, is_tty),
                    ResolvedOutputFormat::Table
                );
            }
        }
    }

    #[test]
    fn non_tty_auto_error_emits_structured_json_envelope() {
        let err = SncfrError::ReadOnlyLocked {
            reason: "SNCFR_READ_ONLY=1".to_string(),
        };
        let rendered = format_error(&err, OutputFormat::Auto, false);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("valid JSON error envelope");
        assert_eq!(parsed["error"]["code"], "READ_ONLY_LOCKED");
        assert_eq!(parsed["error"]["exit_code"], 6);
    }

    #[test]
    fn formats_osc8_clickable_terminal_hyperlink() {
        let link = osc8_link(
            "https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=123",
            "INC0010042",
        );
        assert_eq!(
            link,
            "\x1b]8;;https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=123\x1b\\INC0010042\x1b]8;;\x1b\\"
        );
        assert!(link.contains("INC0010042"));
    }
}
