//! End-to-end checks for Instance Pack loading through the real binary (ADR-0004).

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::{TempDir, tempdir};

const PROFILE_PACK: &str = r#"schema_version = 1
pack_version = "1"
name = "example-corp"
instances = ["example.service-now.com"]

[auth]
allow_credentials_file = false
"#;

const OVERRIDE_PACK_WITHOUT_AUTH: &str = r#"schema_version = 1
pack_version = "1"
name = "override"
instances = ["example.service-now.com"]
"#;

/// A config dir whose `prod` profile points at `profile.pack.toml` by a *relative* path, which
/// must resolve against the config directory rather than the current directory.
fn setup(extra_profile_toml: &str) -> TempDir {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_profile = \"prod\"\n\n[profiles.prod]\ninstance = \"https://example.service-now.com\"\npack = \"profile.pack.toml\"\n{extra_profile_toml}"
        ),
    )
    .expect("write config");
    fs::write(dir.path().join("profile.pack.toml"), PROFILE_PACK).expect("write pack");
    fs::write(
        dir.path().join("override.pack.toml"),
        OVERRIDE_PACK_WITHOUT_AUTH,
    )
    .expect("write override");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sncfr"))
        .args(args)
        // Run from elsewhere so a CWD-relative pack path would not be found.
        .current_dir(std::env::temp_dir())
        .env("SNCFR_CONFIG", dir.join("config.toml"))
        .env("SNCFR_CACHE_DIR", dir.join("cache"))
        .env("SNCFR_CREDENTIALS_FILE", dir.join("creds.json"))
        .env_remove("SNCFR_PACK")
        .env_remove("SNCFR_INSTANCE")
        .env_remove("SNCFR_PROFILE")
        .output()
        .expect("run sncfr")
}

const COMMANDS: &[&[&str]] = &[
    &[
        "--no-interactive",
        "auth",
        "import",
        "--cookie",
        "JSESSIONID=x",
        "--user-token",
        "t",
    ],
    &["--no-interactive", "auth", "status"],
    &["--no-interactive", "auth", "logout"],
    &["--no-interactive", "auth", "login"],
    &["--no-interactive", "list"],
];

#[test]
fn pack_forbidding_credential_files_stops_every_command_before_the_file_is_touched() {
    // CT-41 (NA-5)
    let dir = setup("");
    for args in COMMANDS {
        let out = run(dir.path(), args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("allow_credentials_file = false"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !dir.path().join("creds.json").exists(),
            "{args:?} created the credentials file"
        );
    }
}

#[test]
fn an_override_pack_cannot_drop_the_profile_packs_credential_file_ban() {
    // CT-41b (NA-4, NA-5)
    let dir = setup("");
    let over = dir.path().join("override.pack.toml");
    let over = over.to_str().expect("utf8 path");
    for args in COMMANDS {
        let mut with_override = vec!["--pack", over];
        with_override.extend_from_slice(args);
        let out = run(dir.path(), &with_override);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !dir.path().join("creds.json").exists(),
            "{args:?} created the credentials file"
        );
    }
}

#[test]
fn pack_locked_profile_rejects_overrides() {
    let dir = setup("pack_locked = true\n");
    let over = dir.path().join("override.pack.toml");
    let out = run(
        dir.path(),
        &[
            "--pack",
            over.to_str().expect("utf8"),
            "--no-interactive",
            "list",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pack_locked"));
}

#[test]
fn invalid_pack_fails_with_pack_invalid_and_location() {
    let dir = setup("");
    fs::write(
        dir.path().join("profile.pack.toml"),
        "schema_version = 1\npack_version = \"1\"\nname = \"x\"\nbogus = 1\n",
    )
    .expect("write bad pack");
    let out = run(dir.path(), &["--json", "--no-interactive", "list"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PACK_INVALID"), "{stderr}");
    assert!(stderr.contains("profile.pack.toml:4:"), "{stderr}");
}
