use clap::Parser;
use sncfr::cli::Cli;
use sncfr::error::SncfrError;
use sncfr::output::{OutputFormat, format_error};
use sncfr::validate_invocation;
use std::io::IsTerminal;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let is_stdout_tty = std::io::stdout().is_terminal();
    let is_stderr_tty = std::io::stderr().is_terminal();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if !err.use_stderr() {
                let _ = err.print();
                return ExitCode::SUCCESS;
            }
            let sncfr_err = SncfrError::InvalidArgs {
                message: err.to_string().trim_end().to_string(),
                remediation: Some(
                    "Run `sncfr --help` to inspect valid flags and subcommands.".to_string(),
                ),
            };
            eprintln!(
                "{}",
                format_error(&sncfr_err, OutputFormat::Auto, is_stderr_tty)
            );
            return sncfr_err.exit_code();
        }
    };

    let output_format = cli.effective_output();
    if let Err(err) = validate_invocation(&cli, is_stdout_tty) {
        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
        return err.exit_code();
    }

    ExitCode::SUCCESS
}
