use clap::Parser;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use sncfr::auth::{
    AuthImportSummary, AuthLoginSummary, AuthLogoutSummary, AuthStatusSummary, CredentialStore,
    can_auto_reauth, execute_auth_import, execute_auth_login, execute_auth_logout,
    execute_auth_status, resolve_authenticated_client,
};
use sncfr::cache::InstanceCache;
use sncfr::cli::{AuthCommands, AuthLoginArgs, Cli, Commands};
use sncfr::config::AppConfig;
use sncfr::doctor::{execute_doctor, format_doctor_report};
use sncfr::dossier::{assemble_ticket_dossier, format_ticket_dossiers};
use sncfr::error::SncfrError;
use sncfr::output::{OutputFormat, ResolvedOutputFormat, format_error};
use sncfr::validate_invocation;
use std::io::IsTerminal;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let is_stdin_tty = std::io::stdin().is_terminal();
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
    let mut config = match AppConfig::load_default() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    };

    let resolved_profile = config.resolve_profile(&cli).ok();
    let (resolved_output, _write_permit) =
        match validate_invocation(&cli, resolved_profile.as_ref(), is_stdout_tty) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                return err.exit_code();
            }
        };

    match &cli.command {
        Commands::Auth(AuthCommands::Profiles) => {
            render_profiles(&config, resolved_output);
            return ExitCode::SUCCESS;
        }
        Commands::Auth(AuthCommands::Login(args)) => {
            let store = CredentialStore::default_store();
            match execute_auth_login(&cli, &mut config, args, &store).await {
                Ok(summary) => {
                    render_auth_login(&summary, resolved_output);
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Auth(AuthCommands::Import(args)) => {
            let store = CredentialStore::default_store();
            match execute_auth_import(&cli, &mut config, args, &store).await {
                Ok(summary) => {
                    render_auth_import(&summary, resolved_output);
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Auth(AuthCommands::Logout) => {
            let profile = match config.resolve_profile(&cli) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let store = CredentialStore::default_store();
            match execute_auth_logout(&profile, &store) {
                Ok(summary) => {
                    render_auth_logout(&summary, resolved_output);
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Auth(AuthCommands::Status) => {
            let profile = match config.resolve_profile(&cli) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let store = CredentialStore::default_store();
            let cache = match InstanceCache::for_instance(&profile.instance_key) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let mut client = match resolve_authenticated_client(
                &cli,
                &mut config,
                &profile,
                &store,
                is_stdin_tty,
                is_stdout_tty,
            )
            .await
            {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let mut res = execute_auth_status(&profile, &client, &cache).await;
            if matches!(res, Err(SncfrError::AuthExpired { .. }))
                && can_auto_reauth(&cli, &profile, is_stdin_tty, is_stdout_tty)
            {
                eprintln!(
                    "ServiceNow session expired for '{}'; launching isolated SSO browser window...",
                    profile.instance_url
                );
                let login_args = AuthLoginArgs {
                    browser: None,
                    timeout_secs: 180,
                };
                if execute_auth_login(&cli, &mut config, &login_args, &store)
                    .await
                    .is_ok()
                    && let Ok(new_client) = resolve_authenticated_client(
                        &cli,
                        &mut config,
                        &profile,
                        &store,
                        false,
                        false,
                    )
                    .await
                {
                    client = new_client;
                    res = execute_auth_status(&profile, &client, &cache).await;
                }
            }
            match res {
                Ok(summary) => {
                    render_auth_status(&summary, resolved_output);
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Doctor => {
            let profile = match config.resolve_profile(&cli) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let store = CredentialStore::default_store();
            let cache = match InstanceCache::for_instance(&profile.instance_key) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let mut client = match resolve_authenticated_client(
                &cli,
                &mut config,
                &profile,
                &store,
                is_stdin_tty,
                is_stdout_tty,
            )
            .await
            {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let mut res = execute_doctor(&profile, &client, &cache).await;
            if matches!(res, Err(SncfrError::AuthExpired { .. }))
                && can_auto_reauth(&cli, &profile, is_stdin_tty, is_stdout_tty)
            {
                eprintln!(
                    "ServiceNow session expired for '{}'; launching isolated SSO browser window...",
                    profile.instance_url
                );
                let login_args = AuthLoginArgs {
                    browser: None,
                    timeout_secs: 180,
                };
                if execute_auth_login(&cli, &mut config, &login_args, &store)
                    .await
                    .is_ok()
                    && let Ok(new_client) = resolve_authenticated_client(
                        &cli,
                        &mut config,
                        &profile,
                        &store,
                        false,
                        false,
                    )
                    .await
                {
                    client = new_client;
                    res = execute_doctor(&profile, &client, &cache).await;
                }
            }
            match res {
                Ok(report) => {
                    println!("{}", format_doctor_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Show(args) => {
            let profile = match config.resolve_profile(&cli) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let store = CredentialStore::default_store();
            let cache = match InstanceCache::for_instance(&profile.instance_key) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
            let client = match resolve_authenticated_client(
                &cli,
                &mut config,
                &profile,
                &store,
                is_stdin_tty,
                is_stdout_tty,
            )
            .await
            {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };

            let mut dossiers = Vec::with_capacity(args.tickets.len());
            for ticket_id in &args.tickets {
                match assemble_ticket_dossier(&client, &cache, args, ticket_id).await {
                    Ok(d) => dossiers.push(d),
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                }
            }
            println!("{}", format_ticket_dossiers(&dossiers, resolved_output));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    ExitCode::SUCCESS
}

fn render_auth_status(summary: &AuthStatusSummary, format: ResolvedOutputFormat) {
    match format {
        ResolvedOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(summary) {
                println!("{json}");
            }
        }
        ResolvedOutputFormat::Yaml => {
            if let Ok(yaml) = serde_yaml::to_string(summary) {
                print!("{yaml}");
            }
        }
        _ => {
            let group_names: Vec<&str> = summary
                .identity
                .groups
                .iter()
                .map(|g| g.name.as_str())
                .collect();
            println!("Profile:    {} ({})", summary.profile, summary.instance_url);
            println!("Auth:       {} (AUTHENTICATED)", summary.auth_method);
            println!(
                "User (@me): {} ({}) [sys_id: {}]",
                summary.identity.display_name, summary.identity.user_name, summary.identity.sys_id
            );
            println!(
                "Groups:     {}",
                if group_names.is_empty() {
                    "(none or dynamic fallback)".to_string()
                } else {
                    group_names.join(", ")
                }
            );
        }
    }
}

fn render_auth_login(summary: &AuthLoginSummary, format: ResolvedOutputFormat) {
    match format {
        ResolvedOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(summary) {
                println!("{json}");
            }
        }
        ResolvedOutputFormat::Yaml => {
            if let Ok(yaml) = serde_yaml::to_string(summary) {
                print!("{yaml}");
            }
        }
        _ => {
            println!(
                "Authenticated via Corporate SSO for profile '{}' ({}) [browser: {}]",
                summary.profile, summary.instance_url, summary.browser_executable
            );
        }
    }
}

fn render_auth_import(summary: &AuthImportSummary, format: ResolvedOutputFormat) {
    match format {
        ResolvedOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(summary) {
                println!("{json}");
            }
        }
        ResolvedOutputFormat::Yaml => {
            if let Ok(yaml) = serde_yaml::to_string(summary) {
                print!("{yaml}");
            }
        }
        _ => {
            println!(
                "Imported {} credentials for profile '{}' ({}) [X-UserToken: {}]",
                summary.credential_kind,
                summary.profile,
                summary.instance_url,
                if summary.has_user_token {
                    "present"
                } else {
                    "missing"
                }
            );
        }
    }
}

fn render_auth_logout(summary: &AuthLogoutSummary, format: ResolvedOutputFormat) {
    match format {
        ResolvedOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(summary) {
                println!("{json}");
            }
        }
        ResolvedOutputFormat::Yaml => {
            if let Ok(yaml) = serde_yaml::to_string(summary) {
                print!("{yaml}");
            }
        }
        _ => {
            if summary.removed {
                println!(
                    "Cleared stored credentials for profile '{}' ({}).",
                    summary.profile, summary.instance_url
                );
            } else {
                println!(
                    "No stored credentials found for profile '{}' ({}).",
                    summary.profile, summary.instance_url
                );
            }
        }
    }
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
