use clap::Parser;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use sncfr::cli::{AuthCommands, Cli, Commands};
use sncfr::config::AppConfig;
use sncfr::error::SncfrError;
use sncfr::output::{OutputFormat, ResolvedOutputFormat, format_error};
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
    let config = match AppConfig::load_default() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    };

    let resolved_profile = config.resolve_profile(&cli).ok();
    let resolved_output = match validate_invocation(&cli, resolved_profile.as_ref(), is_stdout_tty)
    {
        Ok(fmt) => fmt,
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    };

    if let Commands::Auth(AuthCommands::Profiles) = &cli.command {
        render_profiles(&config, resolved_output);
        return ExitCode::SUCCESS;
    }

    ExitCode::SUCCESS
}

fn render_profiles(config: &AppConfig, format: ResolvedOutputFormat) {
    match format {
        ResolvedOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(config) {
                println!("{json}");
            }
        }
        ResolvedOutputFormat::Yaml => {
            if let Ok(yaml) = serde_yaml::to_string(config) {
                print!("{yaml}");
            }
        }
        _ => {
            if config.profiles.is_empty() {
                println!("No profiles configured in ~/.config/sncfr/config.toml.");
                return;
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "PROFILE",
                    "DEFAULT",
                    "INSTANCE",
                    "AUTH",
                    "READ_ONLY",
                    "SAVED_VIEWS",
                ]);

            for (name, prof) in &config.profiles {
                let is_default = config.default_profile.as_deref() == Some(name.as_str())
                    || (config.default_profile.is_none()
                        && (name == "default" || config.profiles.len() == 1));
                let views: Vec<&str> = prof.views.keys().map(String::as_str).collect();
                table.add_row(vec![
                    name.as_str(),
                    if is_default { "*" } else { "" },
                    prof.instance.as_str(),
                    prof.auth_method.as_str(),
                    if prof.read_only { "true" } else { "false" },
                    &views.join(", "),
                ]);
            }
            println!("{table}");
        }
    }
}
