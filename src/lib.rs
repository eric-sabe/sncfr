pub mod auth;
pub mod cache;
pub mod capabilities;
pub mod catalog;
pub mod cli;
pub mod client;
pub mod cmdb;
pub mod config;
pub mod discover;
pub mod doctor;
pub mod dossier;
pub mod error;
pub mod list;
pub mod log;
pub mod monitor;
pub mod mutate;
pub mod output;
pub mod pack;
pub mod policy;
pub mod query;
pub mod references;
pub mod resolve;
pub mod resolve_value;
pub mod schema;
pub mod skill;
pub mod untrusted;
pub mod workflows;
pub use client::write_gate;

use crate::cli::Cli;
use crate::client::WritePermit;
use crate::config::ResolvedProfile;
use crate::error::SncfrError;
use crate::output::ResolvedOutputFormat;

/// Validates top-level CLI invariants (including issuing/verifying [`WritePermit`] eligibility
/// when `--write` is passed) and resolves the concrete output format for the invocation.
pub fn validate_invocation(
    cli: &Cli,
    profile: Option<&ResolvedProfile>,
    is_tty: bool,
) -> Result<(ResolvedOutputFormat, Option<WritePermit>), SncfrError> {
    let permit = WritePermit::issue(cli, profile)?;
    let fmt = cli
        .effective_output()
        .resolve_with_tty(cli.command.output_shape(), is_tty);
    Ok((fmt, permit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, AuthMethod, ProfileConfig};
    use clap::Parser;
    use std::collections::BTreeMap;

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

        let err = validate_invocation(&cli, None, false).expect_err("should block --write");
        assert_eq!(err.code().exit_code(), 6);
    }

    #[test]
    fn rejects_write_when_profile_read_only_is_true() {
        let mut cfg = AppConfig {
            default_profile: Some("prod".to_string()),
            profiles: BTreeMap::new(),
        };
        cfg.profiles.insert(
            "prod".to_string(),
            ProfileConfig {
                instance: "https://mycompany.service-now.com".to_string(),
                auth_method: AuthMethod::Sso,
                username: None,
                read_only: true,
                views: BTreeMap::new(),
                ..Default::default()
            },
        );

        let cli = Cli::try_parse_from(["sncfr", "comment", "INC0010042", "Testing", "--write"])
            .expect("parse cli");
        let resolved = cfg.resolve_profile(&cli).expect("resolve profile");

        let err =
            validate_invocation(&cli, Some(&resolved), false).expect_err("profile lock blocks");
        assert_eq!(err.code().exit_code(), 6);
    }

    #[test]
    fn allows_dry_run_when_read_only_lock_is_active() {
        let cli = Cli::try_parse_from(["sncfr", "--read-only", "comment", "INC0010042", "Testing"])
            .expect("parse cli");

        let (fmt, permit) =
            validate_invocation(&cli, None, false).expect("dry-run is allowed in read-only mode");
        assert_eq!(fmt, ResolvedOutputFormat::Md);
        assert!(permit.is_none());
    }
}
