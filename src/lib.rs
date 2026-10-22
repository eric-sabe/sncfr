pub mod cli;
pub mod error;
pub mod output;

use crate::cli::Cli;
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;

/// Validates top-level CLI invariants (such as the hard read-only lock when `--write` is passed)
/// and resolves the concrete output format for the invocation.
pub fn validate_invocation(cli: &Cli, is_tty: bool) -> Result<ResolvedOutputFormat, SncfrError> {
    if cli.read_only && cli.command.requests_write() {
        return Err(SncfrError::ReadOnlyLocked {
            reason: "`--read-only` / `SNCFR_READ_ONLY` is active while `--write` was requested"
                .to_string(),
        });
    }

    Ok(cli
        .effective_output()
        .resolve_with_tty(cli.command.output_shape(), is_tty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn rejects_write_when_read_only_lock_is_active() {
        let cli = Cli::try_parse_from([
            "sncfr",
            "--read-only",
            "comment",
            "INC0010042",
            "Testing",
            "--write",
        ])
        .expect("parse cli");

        let err = validate_invocation(&cli, false).expect_err("should block --write");
        assert_eq!(err.code().exit_code(), 6);
    }

    #[test]
    fn allows_dry_run_when_read_only_lock_is_active() {
        let cli = Cli::try_parse_from(["sncfr", "--read-only", "comment", "INC0010042", "Testing"])
            .expect("parse cli");

        let fmt = validate_invocation(&cli, false).expect("dry-run is allowed in read-only mode");
        assert_eq!(fmt, ResolvedOutputFormat::Md);
    }
}
