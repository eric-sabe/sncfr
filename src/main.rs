use clap::Parser;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use sncfr::auth::{
    AuthImportSummary, AuthLoginSummary, AuthLogoutSummary, AuthStatusSummary, CredentialStore,
    can_auto_reauth, execute_auth_import, execute_auth_login, execute_auth_logout,
    execute_auth_status, resolve_authenticated_client,
};
use sncfr::cache::InstanceCache;
use sncfr::cli::{
    ApprovalCommands, AuthCommands, AuthLoginArgs, CatalogCommands, Cli, Commands, PackCommands,
    SkillCommands,
};
use sncfr::client::{ReadOnlyClient, WritePermit};
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
    if let Err(err) = sncfr::log::init(cli.verbose, cli.log_file.as_deref()) {
        eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
        return err.exit_code();
    }

    let mut config = match AppConfig::load_default() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    };

    let resolved_profile = config.resolve_profile(&cli).ok();
    if let Some(prof) = &resolved_profile {
        sncfr::debug_log!(
            "config",
            "Resolved profile '{}' -> instance={} (key={}, auth={}, read_only_locked={})",
            prof.name,
            prof.instance_url,
            prof.instance_key,
            prof.auth_method.as_str(),
            prof.is_read_only_locked()
        );
    } else {
        sncfr::debug_log!(
            "config",
            "No profile resolved yet (cli.profile={:?}, cli.instance={:?}, configured_profiles={})",
            cli.profile,
            cli.instance,
            config.profiles.len()
        );
    }

    // Load and install the Instance Pack before anything can select a credential store (NA-5).
    // `pack validate` checks an arbitrary file, so it must still run when the configured pack fails.
    let validating_pack = matches!(&cli.command, Commands::Pack(PackCommands::Validate { .. }));
    match load_instance_pack(&cli, resolved_profile.as_ref()) {
        Ok(pack) => {
            sncfr::debug_log!(
                "pack",
                "Loaded Instance Pack '{}' {} ({} layer(s))",
                pack.name,
                pack.short_hash(),
                pack.layers.len()
            );
            if !sncfr::pack::install(pack) {
                let err = SncfrError::InvalidArgs {
                    message: "internal error: the Instance Pack was read before it was installed"
                        .to_string(),
                    remediation: None,
                };
                eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                return err.exit_code();
            }
        }
        Err(_) if validating_pack => {}
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    }

    match sncfr::write_gate::AllowList::parse(&cli.allow_unverified) {
        Ok(list) => {
            sncfr::write_gate::install_allow_list(list);
        }
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
    }

    // A pack describes specific instances: writes elsewhere are refused, reads get a warning (NA-14).
    if let Some(prof) = &resolved_profile
        && !sncfr::pack::active().binds(&prof.instance_key)
    {
        let err = SncfrError::PackNotForInstance {
            pack: sncfr::pack::active().name.clone(),
            instance: prof.instance_key.clone(),
        };
        if cli.command.requests_write() {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            return err.exit_code();
        }
        eprintln!("warning: {err}");
    }

    let (resolved_output, write_permit) =
        match validate_invocation(&cli, resolved_profile.as_ref(), is_stdout_tty) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                return err.exit_code();
            }
        };
    sncfr::debug_log!(
        "cli",
        "Validated invocation: resolved_output={:?}, write_permit={}",
        resolved_output,
        write_permit.is_some()
    );

    match &cli.command {
        Commands::Auth(AuthCommands::Profiles) => {
            render_profiles(&config, resolved_output);
            return ExitCode::SUCCESS;
        }
        Commands::Auth(AuthCommands::Login(args)) => {
            let store = match CredentialStore::default_store() {
                Ok(store) => store,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
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
            let store = match CredentialStore::default_store() {
                Ok(store) => store,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
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
            let store = match CredentialStore::default_store() {
                Ok(store) => store,
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    return err.exit_code();
                }
            };
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
        Commands::Pack(PackCommands::Validate { path }) => {
            return match sncfr::pack::report::execute_pack_validate(path) {
                Ok(v) => {
                    println!(
                        "{}",
                        sncfr::pack::report::format_pack_validation(&v, resolved_output)
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    err.exit_code()
                }
            };
        }
        Commands::Pack(PackCommands::Show { toml }) => {
            return match sncfr::pack::report::format_pack_show(
                sncfr::pack::active(),
                *toml,
                resolved_output,
            ) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
                    err.exit_code()
                }
            };
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
        _ => {}
    }

    let mut result = execute_authenticated_command(
        &cli,
        &mut config,
        resolved_output,
        write_permit,
        is_stdin_tty,
        is_stdout_tty,
    )
    .await;

    if matches!(result, Err(SncfrError::AuthExpired { .. }))
        && let Ok(profile) = config.resolve_profile(&cli)
        && can_auto_reauth(&cli, &profile, is_stdin_tty, is_stdout_tty)
        && let Ok(store) = CredentialStore::default_store()
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
            && let Ok((_, retry_permit)) = validate_invocation(&cli, Some(&profile), is_stdout_tty)
        {
            result = execute_authenticated_command(
                &cli,
                &mut config,
                resolved_output,
                retry_permit,
                false,
                false,
            )
            .await;
        }
    }

    match result {
        Ok(rendered) => {
            if !rendered.is_empty() {
                println!("{rendered}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", format_error(&err, output_format, is_stderr_tty));
            err.exit_code()
        }
    }
}

/// Renders a mutation report. When the report implies exit 8 (unverifiable values) or 9 (fields
/// not applied), the report still goes to stdout and the error envelope to stderr.
fn emit_mutation(
    report: &sncfr::mutate::MutationReport,
    format: ResolvedOutputFormat,
) -> Result<String, SncfrError> {
    let rendered = format_mutation_report(report, format);
    match sncfr::mutate::report_error(report) {
        Some(err) => {
            println!("{rendered}");
            Err(err)
        }
        None => Ok(rendered),
    }
}

/// Loads `ootb` ⊕ the profile's `pack =` ⊕ `--pack`/`SNCFR_PACK` (ADR-0004).
fn load_instance_pack(
    cli: &Cli,
    profile: Option<&ResolvedProfile>,
) -> Result<sncfr::pack::MergedPack, SncfrError> {
    if cli.pack.is_some() && profile.is_some_and(|p| p.pack_locked) {
        return Err(SncfrError::InvalidArgs {
            message: format!(
                "Profile '{}' has `pack_locked = true`; `--pack` / `SNCFR_PACK` overrides are not allowed",
                profile.map_or("", |p| p.name.as_str())
            ),
            remediation: Some(
                "Drop `--pack` / unset SNCFR_PACK, or change `pack =` in config.toml.".to_string(),
            ),
        });
    }
    sncfr::pack::load_layers(
        profile.and_then(|p| p.pack_path.as_deref()),
        cli.pack.as_deref(),
    )
}

async fn execute_authenticated_command(
    cli: &Cli,
    config: &mut AppConfig,
    resolved_output: ResolvedOutputFormat,
    write_permit: Option<WritePermit>,
    is_stdin_tty: bool,
    is_stdout_tty: bool,
) -> Result<String, SncfrError> {
    let (profile, cache, client) =
        prepare_read_context(cli, config, is_stdin_tty, is_stdout_tty).await?;

    match &cli.command {
        Commands::Auth(AuthCommands::Status) => {
            let summary = execute_auth_status(&profile, &client, &cache).await?;
            render_auth_status(&summary, resolved_output);
            Ok(String::new())
        }
        Commands::Doctor => {
            let report = execute_doctor(&profile, &client, &cache).await?;
            Ok(format_doctor_report(&report, resolved_output))
        }
        Commands::Show(args) => {
            let mut dossiers = Vec::with_capacity(args.tickets.len());
            for ticket_id in &args.tickets {
                dossiers.push(assemble_ticket_dossier(&client, &cache, args, ticket_id).await?);
            }
            Ok(format_ticket_dossiers(&dossiers, resolved_output))
        }
        Commands::List(args) => {
            let env = execute_list(&profile, &client, &cache, args).await?;
            Ok(format_record_list(&env, resolved_output))
        }
        Commands::Search(args) => {
            let env = execute_search(&client, &cache, args).await?;
            Ok(format_record_list(&env, resolved_output))
        }
        Commands::Table(args) => {
            let env = execute_table(&client, &cache, args).await?;
            Ok(format_record_list(&env, resolved_output))
        }
        Commands::Stats(args) => {
            let env = execute_stats(&profile, &client, &cache, args).await?;
            Ok(format_stats(&env, resolved_output))
        }
        Commands::Feed(args) => {
            let env = execute_feed(&profile, &client, &cache, args).await?;
            Ok(format_feed(&env, resolved_output))
        }
        Commands::Attachments(args) => {
            let env = execute_attachments(&client, &cache, args).await?;
            Ok(format_attachments(&env, resolved_output))
        }
        Commands::Schema(args) => {
            let schema = execute_schema(&client, &cache, args).await?;
            Ok(format_schema(&schema, args, resolved_output))
        }
        Commands::Comment(args) => {
            let report = execute_comment_or_note(client, &cache, args, false, write_permit).await?;
            emit_mutation(&report, resolved_output)
        }
        Commands::Note(args) => {
            let report = execute_comment_or_note(client, &cache, args, true, write_permit).await?;
            emit_mutation(&report, resolved_output)
        }
        Commands::Update(args) => {
            let report = execute_update(client, &cache, args, write_permit).await?;
            emit_mutation(&report, resolved_output)
        }
        Commands::Create(args) => {
            let report = execute_create(client, &cache, args, write_permit).await?;
            emit_mutation(&report, resolved_output)
        }
        Commands::Attach(args) => {
            let report = execute_attach(client, &cache, args, write_permit).await?;
            emit_mutation(&report, resolved_output)
        }
        Commands::Approvals(subcmd) => match subcmd {
            ApprovalCommands::List(args) => {
                let env = execute_approvals_list(&client, &cache, args).await?;
                Ok(format_approvals(&env, resolved_output))
            }
            ApprovalCommands::Show { approval_or_ticket } => {
                let env = execute_approvals_show(&client, &cache, approval_or_ticket).await?;
                Ok(format_approvals(&env, resolved_output))
            }
            ApprovalCommands::Approve(args) => {
                let report =
                    execute_approval_action(client, &cache, args, true, write_permit).await?;
                emit_mutation(&report, resolved_output)
            }
            ApprovalCommands::Reject(args) => {
                let report =
                    execute_approval_action(client, &cache, args, false, write_permit).await?;
                emit_mutation(&report, resolved_output)
            }
        },
        Commands::Catalog(subcmd) => match subcmd {
            CatalogCommands::Search { query, limit } => {
                let items = execute_catalog_search(&client, query, *limit).await?;
                Ok(format_catalog_search(&items, resolved_output))
            }
            CatalogCommands::Show { item } => {
                let detail = execute_catalog_show(&client, item).await?;
                Ok(format_catalog_detail(&detail, resolved_output))
            }
            CatalogCommands::Order(args) => {
                let report = execute_catalog_order(client, &cache, args, write_permit).await?;
                emit_mutation(&report, resolved_output)
            }
        },
        Commands::Auth(_) | Commands::Skill(_) | Commands::Pack(_) => unreachable!(),
    }
}

async fn prepare_read_context(
    cli: &Cli,
    config: &mut AppConfig,
    is_stdin_tty: bool,
    is_stdout_tty: bool,
) -> Result<(ResolvedProfile, InstanceCache, ReadOnlyClient), SncfrError> {
    let profile = config.resolve_profile(cli)?;
    let store = CredentialStore::default_store()?;
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
            println!("Pack:       {}", summary.pack.headline());
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
                "Authenticated via Corporate SSO for profile '{}' ({}) [browser: {}, X-UserToken: {}]",
                summary.profile,
                summary.instance_url,
                summary.browser_executable,
                if summary.has_user_token {
                    "present"
                } else {
                    "missing"
                }
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
