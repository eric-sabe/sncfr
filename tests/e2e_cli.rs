use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn e2e_cli_full_workflow_auth_doctor_show_list_stats_dry_run_write_and_skill() {
    let server = MockServer::start().await;
    let bin = env!("CARGO_BIN_EXE_sncfr");
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("config.toml");
    let cache_dir = dir.path().join("cache");
    let creds_file = dir.path().join("creds.json");

    // 1. Seed `config.toml` with a saved view `@team-triage`
    let initial_toml = format!(
        r#"default_profile = "prod"

[profiles.prod]
instance = "{}"
auth_method = "sso"
read_only = false

[profiles.prod.views]
team-triage = {{ table = "incident", query = "assignment_group.name=Cloud Platform" }}
"#,
        server.uri()
    );
    fs::write(&config_path, initial_toml).expect("write initial config");

    // 2. Import credentials via `sncfr auth import --file`
    let curl_file = dir.path().join("curl.txt");
    fs::write(
        &curl_file,
        format!(
            "curl '{}/api/now/ui/user/current_user' -H 'X-UserToken: gck_0123456789abcdef0123456789abcdef' -b 'JSESSIONID=e2e_sess; glide_user_route=glide.1'",
            server.uri()
        ),
    )
    .expect("write curl file");

    let import_out = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args([
            "auth",
            "import",
            "--file",
            curl_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run auth import");
    assert!(
        import_out.status.success(),
        "auth import stderr: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );
    let import_json: Value = serde_json::from_slice(&import_out.stdout).expect("import json");
    assert_eq!(import_json["has_user_token"], true);

    // 3. Mount Mock Endpoints on `wiremock`
    Mock::given(method("GET"))
        .and(path("/api/now/table/sys_user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{
                "sys_id": { "value": "u_eric", "display_value": "u_eric" },
                "user_name": { "value": "eric.sabe", "display_value": "eric.sabe" },
                "name": { "value": "Eric Sabe", "display_value": "Eric Sabe" },
                "email": { "value": "eric@example.com", "display_value": "eric@example.com" }
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/table/sys_user_grmember"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{
                "group": { "value": "g_cloud", "display_value": "Cloud Platform" }
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/table/sys_number"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{
                "prefix": "SEC",
                "category": "u_security_incident"
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/table/incident"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{
                "sys_id": { "value": "inc_42", "display_value": "inc_42" },
                "number": { "value": "INC0010042", "display_value": "INC0010042" },
                "sys_class_name": { "value": "incident", "display_value": "Incident" },
                "state": { "value": "1", "display_value": "New" },
                "priority": { "value": "1", "display_value": "1 - Critical" },
                "short_description": { "value": "Core router packet loss", "display_value": "Core router packet loss" },
                "u_datacenter": { "value": "us-east-va1", "display_value": "US East (VA1)" },
                "comments_and_work_notes": {
                    "value": "2026-10-22 10:00:00 - NOC\nPacket loss detected on uplink.",
                    "display_value": "2026-10-22 10:00:00 - NOC\nPacket loss detected on uplink."
                }
            }]
        })))
        .mount(&server)
        .await;

    let empty_b64 = BASE64_STANDARD.encode(json!({ "result": [] }).to_string());
    let forbidden_b64 =
        BASE64_STANDARD.encode(json!({ "error": { "message": "ACL Restricted" } }).to_string());

    Mock::given(method("POST"))
        .and(path("/api/now/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "batch_request_id": "dossier-INC0010042",
            "serviced_requests": [
                { "id": "journal", "status_code": 403, "body": forbidden_b64 },
                { "id": "child_tasks", "status_code": 200, "body": empty_b64 },
                { "id": "approvals", "status_code": 200, "body": empty_b64 },
                { "id": "impacted_cis", "status_code": 200, "body": empty_b64 },
                { "id": "attachments", "status_code": 200, "body": empty_b64 }
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/stats/incident"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [{
                "stats": { "count": "7" },
                "groupby_fields": [{ "field": "state", "value": "1", "display_value": "New" }]
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/table/sys_dictionary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": [] })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/now/table/sys_choice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                {
                    "name": { "value": "incident", "display_value": "Incident" },
                    "element": { "value": "state", "display_value": "state" },
                    "label": { "value": "New", "display_value": "New" },
                    "value": { "value": "1", "display_value": "1" },
                    "sequence": { "value": "1", "display_value": "1" }
                },
                {
                    "name": { "value": "incident", "display_value": "Incident" },
                    "element": { "value": "state", "display_value": "state" },
                    "label": { "value": "In Progress", "display_value": "In Progress" },
                    "value": { "value": "2", "display_value": "2" },
                    "sequence": { "value": "2", "display_value": "2" }
                }
            ]
        })))
        .mount(&server)
        .await;

    // 4. Verify `sncfr auth status --json`
    let status_out = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args(["auth", "status", "--json"])
        .output()
        .expect("run auth status");
    assert!(status_out.status.success());
    let status_json: Value = serde_json::from_slice(&status_out.stdout).expect("status json");
    assert_eq!(status_json["identity"]["user_name"], "eric.sabe");

    // 5. Verify `sncfr show INC0010042` (piped `auto` -> Markdown Ticket Dossier)
    let show_md_out = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args(["show", "INC0010042"])
        .output()
        .expect("run show");
    assert!(show_md_out.status.success());
    let show_md = String::from_utf8_lossy(&show_md_out.stdout);
    assert!(show_md.contains("# INC0010042 — Core router packet loss"));
    assert!(show_md.contains("u_datacenter"));
    assert!(show_md.contains("US East (VA1)"));
    assert!(show_md.contains("Packet loss detected on uplink."));

    // 6. Verify `sncfr list @team-triage --active` (piped `auto` -> JSON)
    let list_out = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args(["list", "@team-triage", "--active"])
        .output()
        .expect("run list");
    assert!(list_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_out.stdout).expect("list json");
    assert_eq!(list_json["count"], 1);
    assert_eq!(list_json["table"], "incident");

    // 7. Verify `sncfr update INC0010042 --state InvalidState` fails with exit code 2 + `valid_choices`
    let bad_update = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args(["update", "INC0010042", "--state", "InvalidState"])
        .output()
        .expect("run bad update");
    assert_eq!(bad_update.status.code(), Some(2));
    let bad_err: Value = serde_json::from_slice(&bad_update.stderr).expect("error envelope json");
    assert_eq!(bad_err["error"]["code"], "VALIDATION_ERROR");
    assert_eq!(
        bad_err["error"]["valid_choices"],
        json!(["New (1)", "In Progress (2)"])
    );

    // 8. Verify Validated Dry-Run Preview (`sncfr update INC0010042 --state "In Progress"` without `--write`)
    let dry_run = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args([
            "update",
            "INC0010042",
            "--state",
            "In Progress",
            "--assign-to",
            "@me",
            "--json",
        ])
        .output()
        .expect("run dry-run update");
    assert!(dry_run.status.success());
    let dry_json: Value = serde_json::from_slice(&dry_run.stdout).expect("dry-run json");
    assert_eq!(dry_json["mode"], "dry_run");

    // 9. Verify `SNCFR_READ_ONLY=1` blocks `--write` with exit code 6 (`READ_ONLY_LOCKED`)
    let locked_write = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .env("SNCFR_READ_ONLY", "1")
        .args(["update", "INC0010042", "--state", "In Progress", "--write"])
        .output()
        .expect("run locked write");
    assert_eq!(locked_write.status.code(), Some(6));

    // 10. Verify `sncfr update INC0010042 --state "In Progress" --write` commits when unlocked
    Mock::given(method("PATCH"))
        .and(path("/api/now/table/incident/inc_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": { "sys_id": "inc_42" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let committed_write = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args([
            "update",
            "INC0010042",
            "--state",
            "In Progress",
            "--write",
            "--json",
        ])
        .output()
        .expect("run committed write");
    assert!(committed_write.status.success());
    let committed_json: Value =
        serde_json::from_slice(&committed_write.stdout).expect("committed json");
    assert_eq!(committed_json["mode"], "committed");

    // 11. Verify `sncfr skill install --path` writes an instance-aware `SKILL.md`
    let skill_path = dir.path().join("skills").join("sncfr").join("SKILL.md");
    let skill_out = Command::new(bin)
        .env("SNCFR_CONFIG", &config_path)
        .env("SNCFR_CACHE_DIR", &cache_dir)
        .env("SNCFR_CREDENTIALS_FILE", &creds_file)
        .args(["skill", "install", "--path", skill_path.to_str().unwrap()])
        .output()
        .expect("run skill install");
    assert!(skill_out.status.success());
    let skill_md = fs::read_to_string(&skill_path).expect("read SKILL.md");
    assert!(skill_md.contains("name: sncfr"));
    assert!(skill_md.contains("@team-triage"));
    assert!(skill_md.contains("Eric Sabe"));
    assert!(skill_md.contains("`SEC*` -> `u_security_incident`"));
}
