use clap::Parser;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use sncfr::auth::{
    AuthImportSummary, AuthLoginSummary, AuthLogoutSummary, AuthStatusSummary, CredentialStore,
    can_auto_reauth, execute_auth_import, execute_auth_login, execute_auth_logout,
    execute_auth_status, resolve_authenticated_client,
};
use sncfr::cache::InstanceCache;
use sncfr::cli::{
    ApprovalCommands, AuthCommands, AuthLoginArgs, CatalogCommands, Cli, Commands, SkillCommands,
};
use sncfr::client::ReadOnlyClient;
use sncfr::config::{AppConfig, ResolvedProfile};
use sncfr::doctor::{execute_doctor, format_doctor_report};
use sncfr::dossier::{assemble_ticket_dossier, format_ticket_dossiers};
use sncfr::error::SncfrError;
use sncfr::list::{execute_list, execute_search, execute_table, format_record_list};
use sncfr::monitor::{
    execute_attachments, execute_feed, execute_stats, format_attachments, format_feed, format_stats,
};
use sncfr::mutate::{
    execute_attach, execute_comment_or_note, execute_create, execute_update, format_mutation_report,
};
use sncfr::output::{OutputFormat, ResolvedOutputFormat, format_error};
use sncfr::schema::{execute_schema, format_schema};
use sncfr::skill::{format_skill_install, generate_skill_markdown, install_skill_markdown};
use sncfr::validate_invocation;
use sncfr::workflows::{
    execute_approval_action, execute_approvals_list, execute_approvals_show, execute_catalog_order,
    execute_catalog_search, execute_catalog_show, format_approvals, format_catalog_detail,
    format_catalog_search,
};
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
    let (resolved_output, write_permit) =
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
            let (profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };

            let _ = profile;
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
        Commands::List(args) => {
            let (profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_list(&profile, &client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_record_list(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Search(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_search(&client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_record_list(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Table(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_table(&client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_record_list(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Stats(args) => {
            let (profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_stats(&profile, &client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_stats(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Feed(args) => {
            let (profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_feed(&profile, &client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_feed(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Attachments(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_attachments(&client, &cache, args).await {
                Ok(env) => {
                    println!("{}", format_attachments(&env, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Schema(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_schema(&client, &cache, args).await {
                Ok(schema) => {
                    println!("{}", format_schema(&schema, args, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Comment(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_comment_or_note(client, &cache, args, false, write_permit).await {
                Ok(report) => {
                    println!("{}", format_mutation_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Note(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_comment_or_note(client, &cache, args, true, write_permit).await {
                Ok(report) => {
                    println!("{}", format_mutation_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Update(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_update(client, &cache, args, write_permit).await {
                Ok(report) => {
                    println!("{}", format_mutation_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Create(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_create(client, &cache, args, write_permit).await {
                Ok(report) => {
                    println!("{}", format_mutation_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Attach(args) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match execute_attach(client, &cache, args, write_permit).await {
                Ok(report) => {
                    println!("{}", format_mutation_report(&report, resolved_output));
                    return ExitCode::SUCCESS;
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            }
        }
        Commands::Approvals(subcmd) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match subcmd {
                ApprovalCommands::List(args) => {
                    match execute_approvals_list(&client, &cache, args).await {
                        Ok(env) => {
                            println!("{}", format_approvals(&env, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
                ApprovalCommands::Show { approval_or_ticket } => {
                    match execute_approvals_show(&client, &cache, approval_or_ticket).await {
                        Ok(env) => {
                            println!("{}", format_approvals(&env, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
                ApprovalCommands::Approve(args) => {
                    match execute_approval_action(client, &cache, args, true, write_permit).await {
                        Ok(report) => {
                            println!("{}", format_mutation_report(&report, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
                ApprovalCommands::Reject(args) => {
                    match execute_approval_action(client, &cache, args, false, write_permit).await {
                        Ok(report) => {
                            println!("{}", format_mutation_report(&report, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
            }
        }
        Commands::Catalog(subcmd) => {
            let (_profile, cache, client) =
                match prepare_read_context(&cli, &mut config, is_stdin_tty, is_stdout_tty).await {
                    Ok(ctx) => ctx,
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                };
            match subcmd {
                CatalogCommands::Search { query, limit } => {
                    match execute_catalog_search(&client, query, *limit).await {
                        Ok(items) => {
                            println!("{}", format_catalog_search(&items, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
                CatalogCommands::Show { item } => match execute_catalog_show(&client, item).await {
                    Ok(detail) => {
                        println!("{}", format_catalog_detail(&detail, resolved_output));
                        return ExitCode::SUCCESS;
                    }
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                },
                CatalogCommands::Order(args) => {
                    match execute_catalog_order(client, &cache, args, write_permit).await {
                        Ok(report) => {
                            println!("{}", format_mutation_report(&report, resolved_output));
                            return ExitCode::SUCCESS;
                        }
                        Err(err) => {
                            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                            return err.exit_code();
                        }
                    }
                }
            }
        }
        Commands::Skill(subcmd) => match subcmd {
            SkillCommands::Print => {
                print!(
                    "{}",
                    generate_skill_markdown(&config, resolved_profile.as_ref())
                );
                return ExitCode::SUCCESS;
            }
            SkillCommands::Install { path } => {
                match install_skill_markdown(path, &config, resolved_profile.as_ref()) {
                    Ok(summary) => {
                        println!("{}", format_skill_install(&summary, resolved_output));
                        return ExitCode::SUCCESS;
                    }
                    Err(err) => {
                        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                        return err.exit_code();
                    }
                }
            }
        },
    }
}

async fn prepare_read_context(
    cli: &Cli,
    config: &mut AppConfig,
    is_stdin_tty: bool,
    is_stdout_tty: bool,
) -> Result<(ResolvedProfile, InstanceCache, ReadOnlyClient), SncfrError> {
    let profile = config.resolve_profile(cli)?;
    let store = CredentialStore::default_store();
    let cache = InstanceCache::for_instance(&profile.instance_key)?;
    let client =
        resolve_authenticated_client(cli, config, &profile, &store, is_stdin_tty, is_stdout_tty)
            .await?;
    Ok((profile, cache, client))
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
