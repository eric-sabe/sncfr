//! Shared "Example Corp" brownfield harness (BF-TEST-1, BF-TEST-4).
//!
//! Everything here is fictional. A wiremock instance plays a locked-down enterprise ServiceNow:
//! renumbered priorities, empty `sys_choice` / `sys_dictionary`, `sys_number` 403, and
//! assignment groups that follow a ` - L2` / ` - L3` suffix convention. The real binary runs
//! against it with `docs/packs/example.pack.toml`, whose `instances` line is rewritten to the
//! mock host so the pack binds.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub const ME_SYS_ID: &str = "11111111111111111111111111111111";
pub const INCIDENT_SYS_ID: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
pub const EXAMPLE_PACK: &str = include_str!("../../docs/packs/example.pack.toml");

fn fixture(name: &str) -> Value {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/example-corp")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// `sys_user_group` lookups against the fixture directory.
struct GroupDirectory(Vec<(String, String)>);

impl GroupDirectory {
    fn from_fixture() -> Self {
        let mut groups = Vec::new();
        for rows in fixture("groups.json")
            .as_object()
            .expect("groups object")
            .values()
        {
            for r in rows.as_array().into_iter().flatten() {
                groups.push((
                    r["name"].as_str().unwrap_or_default().to_string(),
                    r["sys_id"].as_str().unwrap_or_default().to_string(),
                ));
            }
        }
        Self(groups)
    }
}

impl Respond for GroupDirectory {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let q = req
            .url
            .query_pairs()
            .find(|(k, _)| k == "sysparm_query")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let matches = |name: &str| -> bool {
            if q.is_empty() {
                return true;
            }
            if let Some(list) = q.strip_prefix("nameIN") {
                return list.split(',').any(|n| n == name);
            }
            if let Some(prefix) = q.strip_prefix("nameSTARTSWITH") {
                return name.starts_with(prefix);
            }
            q.split("^OR")
                .any(|t| t.strip_prefix("name=") == Some(name))
        };
        let rows: Vec<Value> = self
            .0
            .iter()
            .filter(|(name, _)| matches(name))
            .map(|(name, sys_id)| {
                json!({
                    "sys_id": { "value": sys_id, "display_value": sys_id },
                    "name": { "value": name, "display_value": name },
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "result": rows }))
    }
}

/// Instance scenarios that can be layered onto the base mocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// `sys_choice` returns the renumbered incident priorities and divergent incident /
    /// sc_req_item states (instead of the default empty result).
    ReadableChoices,
    /// `/api/now/batch` answers 400 "Requested URI does not represent any resource".
    BatchUriNotResource,
    /// `sys_journal_field` answers after 2 s (past a `--timeout 1`).
    SlowJournal,
    /// `/api/now/stats/incident` group-by answers with in-use values: renumbered priorities
    /// (0–5, `5 - Low`) and `u_tier` = silver, bronze (`in_use.json` "renumbered").
    InUseRenumbered,
    /// Like [`Scenario::InUseRenumbered`], but the in-use priorities are OOTB, with `4 - Low`.
    InUseOotbLow,
    /// `/api/now/stats/*` answers 403.
    StatsUnauthorized,
    /// `task` answers with recent rows (`number`, `sys_class_name`): three `ABC-` rows on
    /// `u_abc_request`, two `INC` rows (`task_sample.json`).
    TaskSample,
}

/// `/api/now/stats/<table>?sysparm_group_by=<field>` against one `in_use.json` set (incident only).
struct InUseStats(Value);

impl Respond for InUseStats {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let field = req
            .url
            .query_pairs()
            .find(|(k, _)| k == "sysparm_group_by")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        // Only incident has in-use data; any other table (or a count without group-by) is empty.
        let data = if req.url.path() == "/api/now/stats/incident" {
            &self.0[field.as_str()]
        } else {
            &Value::Null
        };
        let rows: Vec<Value> = data
            .as_array()
            .into_iter()
            .flatten()
            .map(|pair| {
                json!({
                    "stats": { "count": "3" },
                    "groupby_fields": [{ "field": field, "value": pair[0], "display_value": pair[1] }]
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "result": rows }))
    }
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}): {}\nstderr: {}",
                self.stdout, self.stderr
            )
        })
    }
}

pub struct ExampleCorp {
    pub server: MockServer,
    dir: TempDir,
    pack_path: PathBuf,
}

impl ExampleCorp {
    /// Starts the mock instance with the base Example Corp mocks and the example pack active.
    pub async fn start() -> Self {
        Self::start_with_pack(EXAMPLE_PACK).await
    }

    /// Starts with no user pack (the bundled ootb pack only).
    pub async fn start_without_pack() -> Self {
        let corp = Self::start_with_pack(EXAMPLE_PACK).await;
        fs::write(
            corp.dir.path().join("config.toml"),
            format!(
                "default_profile = \"prod\"\n\n[profiles.prod]\ninstance = \"{}\"\nauth_method = \"api-key\"\n",
                corp.server.uri()
            ),
        )
        .expect("write config");
        corp
    }

    /// Starts with a custom pack text; `instances = ["example.service-now.com"]` is rewritten to
    /// the mock host.
    pub async fn start_with_pack(pack_text: &str) -> Self {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key = server.uri().trim_start_matches("http://").replace(':', "_");
        let pack_path = dir.path().join("example-corp.pack.toml");
        fs::write(
            &pack_path,
            pack_text.replace(
                "instances = [\"example.service-now.com\"]",
                &format!("instances = [\"{host_key}\"]"),
            ),
        )
        .expect("write pack");
        fs::write(
            dir.path().join("config.toml"),
            format!(
                "default_profile = \"prod\"\n\n[profiles.prod]\ninstance = \"{}\"\nauth_method = \"api-key\"\npack = \"example-corp.pack.toml\"\n",
                server.uri()
            ),
        )
        .expect("write config");
        let corp = Self {
            server,
            dir,
            pack_path,
        };
        corp.mount_base().await;
        corp
    }

    pub fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    /// A file in this instance's cache directory (e.g. `capabilities.json`).
    pub fn cache_file(&self, name: &str) -> PathBuf {
        let key = self
            .server
            .uri()
            .trim_start_matches("http://")
            .replace(':', "_");
        self.dir.path().join("cache").join(key).join(name)
    }

    async fn get(&self, table: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(format!("/api/now/table/{table}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn mount_base(&self) {
        let identity = fixture("identity.json");
        self.get("sys_user", identity["sys_user"].clone()).await;
        self.get("sys_user_grmember", identity["sys_user_grmember"].clone())
            .await;
        self.get("incident", fixture("incident.json")).await;
        self.get("u_abc_request", fixture("abc_request.json")).await;
        self.get("sys_choice", json!({ "result": [] })).await;
        self.get("sys_dictionary", json!({ "result": [] })).await;
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_number"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "error": { "message": "Insufficient rights" } })),
            )
            .mount(&self.server)
            .await;
        // Group directory (suffix convention: " - L2", " - L3"); answers name=, nameIN,
        // ^OR chains of name=, and nameSTARTSWITH queries.
        Mock::given(method("GET"))
            .and(path("/api/now/table/sys_user_group"))
            .respond_with(GroupDirectory::from_fixture())
            .mount(&self.server)
            .await;
    }

    pub async fn mount(&self, scenario: Scenario) {
        match scenario {
            Scenario::BatchUriNotResource => {
                Mock::given(method("POST"))
                    .and(path("/api/now/batch"))
                    .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                        "error": { "message": "Requested URI does not represent any resource", "detail": null }
                    })))
                    .mount(&self.server)
                    .await;
            }
            Scenario::SlowJournal => {
                Mock::given(method("GET"))
                    .and(path("/api/now/table/sys_journal_field"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({ "result": [] }))
                            .set_delay(std::time::Duration::from_secs(2)),
                    )
                    .mount(&self.server)
                    .await;
            }
            Scenario::InUseRenumbered | Scenario::InUseOotbLow => {
                let key = if scenario == Scenario::InUseRenumbered {
                    "renumbered"
                } else {
                    "ootb_low"
                };
                Mock::given(method("GET"))
                    .and(wiremock::matchers::path_regex("^/api/now/stats/"))
                    .respond_with(InUseStats(fixture("in_use.json")[key].clone()))
                    .mount(&self.server)
                    .await;
            }
            Scenario::TaskSample => {
                self.get("task", fixture("task_sample.json")).await;
            }
            Scenario::StatsUnauthorized => {
                Mock::given(method("GET"))
                    .and(wiremock::matchers::path_regex("^/api/now/stats/"))
                    .respond_with(
                        ResponseTemplate::new(403).set_body_json(
                            json!({ "error": { "message": "Insufficient rights" } }),
                        ),
                    )
                    .mount(&self.server)
                    .await;
            }
            Scenario::ReadableChoices => {
                // Mounted later, so it takes priority over the base empty sys_choice mock.
                Mock::given(method("GET"))
                    .and(path("/api/now/table/sys_choice"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(fixture("choices_readable.json")),
                    )
                    .with_priority(1)
                    .mount(&self.server)
                    .await;
            }
        }
    }

    /// Mounts `PATCH /api/now/table/incident/<sys_id>` answering with `record` (the `result`).
    pub async fn mount_incident_patch(&self, record: Value) {
        Mock::given(method("PATCH"))
            .and(path(format!("/api/now/table/incident/{INCIDENT_SYS_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": record })))
            .mount(&self.server)
            .await;
    }

    /// Request bodies of every PATCH sent.
    pub async fn patch_bodies(&self) -> Vec<Value> {
        self.requests()
            .await
            .into_iter()
            .filter(|r| r.method.as_str() == "PATCH")
            .map(|r| serde_json::from_slice(&r.body).unwrap_or(Value::Null))
            .collect()
    }

    /// Runs the real binary non-interactively against the mock instance.
    pub fn run(&self, args: &[&str]) -> Run {
        let out = Command::new(env!("CARGO_BIN_EXE_sncfr"))
            .arg("--no-interactive")
            .args(args)
            .env("SNCFR_CONFIG", self.dir.path().join("config.toml"))
            .env("SNCFR_CACHE_DIR", self.dir.path().join("cache"))
            .env("SNCFR_API_KEY", "example-corp-test-key")
            .env_remove("SNCFR_CREDENTIALS_FILE")
            .env_remove("SNCFR_PACK")
            .env_remove("SNCFR_INSTANCE")
            .env_remove("SNCFR_PROFILE")
            .env_remove("SNCFR_READ_ONLY")
            .output()
            .expect("run sncfr");
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    pub async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    /// Requests that could change instance state: anything but GET/HEAD and all-GET batch POSTs.
    pub async fn mutating_requests(&self) -> Vec<Request> {
        self.requests()
            .await
            .into_iter()
            .filter(|r| {
                let m = r.method.as_str();
                if m == "GET" || m == "HEAD" {
                    return false;
                }
                if m == "POST" && r.url.path() == "/api/now/batch" {
                    let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                    let all_get = body["rest_requests"]
                        .as_array()
                        .is_some_and(|reqs| reqs.iter().all(|q| q["method"] == "GET"));
                    return !all_get;
                }
                true
            })
            .collect()
    }

    /// Every query string sent to `path`.
    pub async fn queries_to(&self, request_path: &str) -> Vec<String> {
        self.requests()
            .await
            .into_iter()
            .filter(|r| r.url.path() == request_path)
            .map(|r| r.url.query().unwrap_or_default().to_string())
            .collect()
    }
}
