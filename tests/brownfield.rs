//! Brownfield ("Example Corp") behavior through the real binary (BF-TEST-1/2).

mod support;

use support::ExampleCorp;

#[tokio::test]
async fn harness_runs_against_a_locked_down_instance_with_the_example_pack() {
    let corp = ExampleCorp::start().await;

    let shown = corp.run(&["--json", "pack", "show"]);
    assert_eq!(shown.code, 0, "{}", shown.stderr);
    assert_eq!(shown.json()["name"], "example-corp");

    let listed = corp.run(&["--json", "list", "--table", "incident"]);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert_eq!(listed.json()["records"][0]["number"], "INC0012345");
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn a_group_name_cannot_smuggle_an_or_clause_into_the_lookup() {
    // CT-66 (NA-13)
    let corp = ExampleCorp::start().await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--group",
        "Nope^ORname=Storage - L2",
        "--write",
    ]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stderr.contains("INVALID_QUERY_VALUE"), "{}", out.stderr);
    assert!(
        corp.queries_to("/api/now/table/sys_user_group")
            .await
            .is_empty()
    );
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn renumbered_priorities_resolve_from_the_pack_with_their_source() {
    // CT-07, CT-09 (SAFE-1, SAFE-2, SAFE-6)
    let corp = ExampleCorp::start().await;
    let low = corp.run(&["--json", "update", "INC0012345", "--priority", "low"]);
    assert_eq!(low.code, 0, "{}", low.stderr);
    let diff = &low.json()["diffs"][0];
    assert_eq!(diff["after_value"], "5");
    assert_eq!(diff["after_display"], "5 - Low");
    assert_eq!(diff["source"], "pack");
    assert_eq!(diff["status"], "verified");

    let four = corp.run(&["--json", "update", "INC0012345", "--priority", "4"]);
    assert_eq!(four.json()["diffs"][0]["after_display"], "4 - Minor");
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn unverifiable_values_block_the_write_and_name_what_would_be_sent() {
    // CT-10 (unknown type), CT-18 (unknown field), dry-run exit 8 (OQ-2) — NA-2
    let corp = ExampleCorp::start().await;
    corp.mount_incident_patch(serde_json::json!({})).await;

    let dry = corp.run(&["--json", "update", "INC0012345", "--set", "u_tier=gold"]);
    assert_eq!(dry.code, 8, "{}", dry.stderr);
    let report = dry.json();
    assert_eq!(report["mode"], "dry_run");
    assert_eq!(
        report["unverifiable_fields"][0]["reason"],
        "unknown_field_type"
    );
    assert_eq!(report["unverifiable_fields"][0]["would_send"], "gold");
    assert!(dry.stderr.contains("UNVERIFIABLE"), "{}", dry.stderr);

    let write = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--set",
        "u_tier=gold",
        "--write",
    ]);
    assert_eq!(write.code, 8, "{}", write.stderr);
    assert_eq!(write.json()["mode"], "blocked");

    let typo = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--set",
        "u_teir=gold",
        "--write",
    ]);
    assert_eq!(typo.code, 8);
    assert_eq!(
        typo.json()["unverifiable_fields"][0]["reason"],
        "unknown_field"
    );

    assert!(
        corp.mutating_requests().await.is_empty(),
        "nothing may be written"
    );
}

#[tokio::test]
async fn allow_unverified_sends_exactly_the_named_fields_as_typed() {
    // CT-11, CT-11b, CT-12 (SAFE-4)
    let corp = ExampleCorp::start().await;
    corp.mount_incident_patch(serde_json::json!({
        "sys_id": { "value": support::INCIDENT_SYS_ID, "display_value": support::INCIDENT_SYS_ID },
        "u_tier": { "value": "gold", "display_value": "gold" }
    }))
    .await;

    let wildcard = corp.run(&[
        "update",
        "INC0012345",
        "--set",
        "u_tier=gold",
        "--allow-unverified",
        "*",
        "--write",
    ]);
    assert_eq!(wildcard.code, 2, "{}", wildcard.stderr);

    let locked = corp.run(&[
        "--read-only",
        "update",
        "INC0012345",
        "--set",
        "u_tier=gold",
        "--write",
    ]);
    assert_eq!(
        locked.code, 6,
        "read-only beats unverifiable: {}",
        locked.stderr
    );
    assert!(corp.mutating_requests().await.is_empty());

    let ok = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--set",
        "u_tier=gold",
        "--allow-unverified",
        "u_tier",
        "--write",
    ]);
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    let report = ok.json();
    assert_eq!(report["mode"], "committed");
    assert_eq!(report["allowed_unverified"][0], "u_tier");
    assert_eq!(
        report["diffs"][0]["status"],
        "allowed unverified (unknown_field_type)"
    );
    let bodies = corp.patch_bodies().await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0], serde_json::json!({ "u_tier": "gold" }));
}

#[tokio::test]
async fn writes_the_instance_did_not_apply_exit_9_and_missing_fields_are_unconfirmed() {
    // CT-19, CT-19b (NA-17)
    let corp = ExampleCorp::start().await;
    corp.mount_incident_patch(serde_json::json!({
        "sys_id": { "value": support::INCIDENT_SYS_ID, "display_value": support::INCIDENT_SYS_ID },
        "priority": { "value": "3", "display_value": "3 - Moderate" }
    }))
    .await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(out.code, 9, "{}", out.stderr);
    let report = out.json();
    assert_eq!(report["not_applied"][0]["field"], "priority");
    assert_eq!(report["not_applied"][0]["sent"], "5");
    assert_eq!(report["not_applied"][0]["returned"], "3");
    assert!(out.stderr.contains("WRITE_NOT_APPLIED"));

    let only_id = ExampleCorp::start().await;
    only_id
        .mount_incident_patch(
            serde_json::json!({ "sys_id": { "value": support::INCIDENT_SYS_ID } }),
        )
        .await;
    let out = only_id.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["unconfirmed"][0], "priority");
}

#[tokio::test]
async fn draft_and_foreign_packs_cannot_authorize_writes() {
    // CT-35b, CT-63 (NA-14)
    let draft = support::EXAMPLE_PACK.replace("status = \"active\"", "status = \"draft\"");
    let corp = ExampleCorp::start_with_pack(&draft).await;
    corp.mount_incident_patch(serde_json::json!({})).await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(out.code, 8, "{}", out.stderr);
    assert_eq!(out.json()["unverifiable_fields"][0]["reason"], "draft_pack");
    assert!(corp.mutating_requests().await.is_empty());

    let foreign = support::EXAMPLE_PACK.replace(
        "instances = [\"example.service-now.com\"]",
        "instances = [\"another.example\"]",
    );
    let corp = ExampleCorp::start_with_pack(&foreign).await;
    let out = corp.run(&["update", "INC0012345", "--priority", "low", "--write"]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr.contains("PACK_NOT_FOR_INSTANCE")
            || out.stderr.contains("does not list instance"),
        "{}",
        out.stderr
    );
    assert!(corp.mutating_requests().await.is_empty());
    let read = corp.run(&["--json", "list", "--table", "incident"]);
    assert_eq!(read.code, 0, "reads still work: {}", read.stderr);
    assert!(read.stderr.contains("warning"), "{}", read.stderr);
}

#[tokio::test]
async fn group_references_follow_the_suffix_convention_but_never_guess() {
    // CT-14 (ambiguous via suffix), CT-15 (unique via suffix) — NA-3, SAFE-7, Q-4
    let corp = ExampleCorp::start().await;
    corp.mount_incident_patch(serde_json::json!({})).await;

    let storage = corp.run(&["--json", "update", "INC0012345", "--group", "Storage"]);
    assert_eq!(storage.code, 0, "{}", storage.stderr);
    let diff = &storage.json()["diffs"][0];
    assert_eq!(diff["after_display"], "Storage - L2");
    assert_eq!(diff["after_value"], "55555555555555555555555555555555");
    assert_eq!(diff["source"], "group:suffix \" - L2\"");

    let network = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--group",
        "Network",
        "--write",
    ]);
    assert_eq!(network.code, 2, "{}", network.stderr);
    assert!(
        network.stderr.contains("AMBIGUOUS_REFERENCE"),
        "{}",
        network.stderr
    );
    assert!(
        network.stderr.contains("Network - L2"),
        "{}",
        network.stderr
    );
    assert!(
        network.stderr.contains("Network - L3"),
        "{}",
        network.stderr
    );
    assert!(
        network.stderr.contains("you are a member"),
        "{}",
        network.stderr
    );
    assert!(
        network.stderr.contains("Network Operations - L2"),
        "suggestion shown: {}",
        network.stderr
    );
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn a_suggest_map_entry_is_never_applied() {
    // CT-15c (SAFE-7)
    let pack = support::EXAMPLE_PACK
        .replace("suffixes = [\" - L2\", \" - L3\"]", "suffixes = []")
        .replace(
            "suggest_map = { \"Network\" = \"Network Operations - L2\" }",
            "suggest_map = { \"Payroll\" = \"Storage - L2\" }",
        );
    let corp = ExampleCorp::start_with_pack(&pack).await;
    corp.mount_incident_patch(serde_json::json!({})).await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--group",
        "Payroll",
        "--write",
    ]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("Suggestion (not applied): Storage - L2"),
        "{}",
        out.stderr
    );
    assert!(corp.patch_bodies().await.is_empty());
}

#[tokio::test]
async fn read_filters_resolve_per_table_and_flag_what_they_cannot_verify() {
    // CT-17b (Q-1): unverifiable filters never block a read but are reported in-band.
    let corp = ExampleCorp::start().await;
    let out = corp.run(&[
        "--json",
        "list",
        "--table",
        "incident",
        "--state",
        "Resolved",
        "--priority",
        "low",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let env = out.json();
    let q = env["query"].as_str().unwrap_or_default();
    assert!(
        q.contains("state=Resolved"),
        "unverified value sent as typed: {q}"
    );
    assert!(q.contains("priority=5"), "pack-resolved value sent: {q}");
    assert_eq!(env["unverified_filters"][0]["field"], "state");
    assert_eq!(env["unverified_filters"][0]["reason"], "no_metadata");

    let md = corp.run(&[
        "-o", "md", "list", "--table", "incident", "--state", "Resolved",
    ]);
    assert!(
        md.stdout
            .contains("⚠ state \"Resolved\" could not be verified for incident"),
        "{}",
        md.stdout
    );
}

#[tokio::test]
async fn a_batch_endpoint_that_does_not_exist_is_remembered_and_skipped() {
    // CT-20 (CAP-2, BF-TEST-2c)
    // The example pack seeds batch_api = false (which alone skips batch, checked below); drop
    // the seed so the observation path is exercised.
    let seeded = ExampleCorp::start().await;
    seeded.mount(support::Scenario::BatchUriNotResource).await;
    assert_eq!(seeded.run(&["--json", "show", "INC0012345"]).code, 0);
    assert!(
        seeded
            .requests()
            .await
            .iter()
            .all(|r| r.url.path() != "/api/now/batch"),
        "pack seed skips batch"
    );

    let corp =
        ExampleCorp::start_with_pack(&support::EXAMPLE_PACK.replace("batch_api = false\n", ""))
            .await;
    corp.mount(support::Scenario::BatchUriNotResource).await;
    let first = corp.run(&["--json", "show", "INC0012345"]);
    assert_eq!(first.code, 0, "{}", first.stderr);
    assert_eq!(first.json()["number"], "INC0012345");
    let caps =
        std::fs::read_to_string(corp.cache_file("capabilities.json")).expect("capabilities.json");
    let caps: serde_json::Value = serde_json::from_str(&caps).expect("json");
    assert_eq!(
        caps["data"]["observations"]["batch_api"]["state"],
        "unavailable"
    );
    assert_eq!(
        caps["data"]["observations"]["batch_api"]["hint"],
        "uri_not_resource"
    );

    let second = corp.run(&["--json", "show", "INC0012345"]);
    assert_eq!(second.code, 0, "{}", second.stderr);
    let batch_posts = corp
        .requests()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/api/now/batch")
        .count();
    assert_eq!(batch_posts, 1, "the second show skips batch");
}

#[tokio::test]
async fn a_slow_section_times_out_alone() {
    // CT-21 (CAP-3, BF-TEST-2d)
    let corp = ExampleCorp::start().await;
    corp.mount(support::Scenario::SlowJournal).await;
    let out = corp.run(&["--json", "--timeout", "1", "show", "INC0012345"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let d = &out.json();
    assert_eq!(d["sections"]["journal"]["status"], "timed_out", "{d}");
    assert!(
        d["degraded"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == "journal"))
    );
    assert_eq!(d["core_fields"]["number"]["display_value"], "INC0012345");

    let md = corp.run(&["-o", "md", "--timeout", "1", "show", "INC0012345"]);
    assert!(
        md.stdout.contains("⚠ Partial dossier:") && md.stdout.contains("journal timed out"),
        "{}",
        md.stdout
    );
}

#[tokio::test]
async fn doctor_reports_absent_tables_drift_binding_and_the_capability_record() {
    // CT-27 (CAP-5), CT-09b doctor half, CAP-6
    let pack = support::EXAMPLE_PACK
        .replace(
            "extra_probe_tables = [\"u_abc_request\"]",
            "extra_probe_tables = [\"u_abc_request\", \"sn_customerservice_case\"]",
        )
        .replace(
            "{ value = \"4\", label = \"4 - Minor\",",
            "{ value = \"4\", label = \"4 - Minor Issue\",",
        );
    let corp = ExampleCorp::start_with_pack(&pack).await;
    corp.mount(support::Scenario::ReadableChoices).await;
    let out = corp.run(&["--json", "doctor", "--refresh"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let r = out.json();
    let absent = r["capabilities"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|c| c["resource"] == "table:sn_customerservice_case")
        })
        .cloned()
        .unwrap_or_default();
    assert_eq!(absent["note"], "not installed", "{absent}");
    assert_eq!(r["pack_binds_instance"], true);
    assert!(
        r["pack_drift"]
            .as_array()
            .is_some_and(
                |d| d.iter().any(|x| x.as_str().unwrap_or_default().contains(
                    "value 4 is \"4 - Minor Issue\" in the pack but \"4 - Minor\" on the instance"
                ))
            ),
        "{}",
        r["pack_drift"]
    );
    let record = r["capability_record"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let catalog = record
        .iter()
        .find(|c| c["capability"] == "catalog_api")
        .cloned()
        .unwrap_or_default();
    assert_eq!(catalog["source"], "probe", "{catalog}");
    assert!(
        r["pack"]["workarounds"]
            .as_array()
            .is_some_and(|w| !w.is_empty())
    );
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn table_reads_never_ask_for_counts_and_list_reads_skip_reference_links() {
    // CT-28 (PERF-1, PERF-4)
    let corp = ExampleCorp::start().await;
    assert_eq!(corp.run(&["--json", "show", "INC0012345"]).code, 0);
    assert_eq!(corp.run(&["--json", "list", "--table", "incident"]).code, 0);
    let mut table_gets = 0;
    for r in corp.requests().await {
        if r.method.as_str() != "GET" || !r.url.path().starts_with("/api/now/table/") {
            continue;
        }
        table_gets += 1;
        let q: Vec<(String, String)> = r
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(
            q.iter()
                .any(|(k, v)| k == "sysparm_no_count" && v == "true"),
            "missing sysparm_no_count on {}",
            r.url
        );
    }
    assert!(table_gets > 3, "{table_gets}");
    let list_reads: Vec<_> = corp
        .requests()
        .await
        .into_iter()
        .filter(|r| {
            r.url.path() == "/api/now/table/incident"
                && r.url.query().unwrap_or_default().contains("ORDERBYDESC")
        })
        .collect();
    assert!(!list_reads.is_empty());
    for r in list_reads {
        assert!(
            r.url
                .query()
                .unwrap_or_default()
                .contains("sysparm_exclude_reference_link=true"),
            "{}",
            r.url
        );
    }
}

#[tokio::test]
async fn list_reports_has_more_without_counting_and_a_total_only_on_request() {
    // PERF-2
    let corp = ExampleCorp::start().await;
    let out = corp.run(&["--json", "list", "--table", "incident", "--limit", "1"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["has_more"], true);
    assert!(out.json().get("total").is_none());

    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/now/table/incident"))
        .and(wiremock::matchers::query_param("sysparm_no_count", "false"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .insert_header("X-Total-Count", "42")
                .set_body_string(
                    std::fs::read_to_string(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/fixtures/example-corp/incident.json"),
                    )
                    .expect("fixture"),
                ),
        )
        .with_priority(1)
        .mount(&corp.server)
        .await;
    let counted = corp.run(&[
        "--json",
        "list",
        "--table",
        "incident",
        "--limit",
        "1",
        "--with-count",
    ]);
    assert_eq!(counted.code, 0, "{}", counted.stderr);
    assert_eq!(counted.json()["total"], 42);
    assert_eq!(counted.json()["has_more"], true);
}

#[tokio::test]
async fn journal_queries_carry_the_table_name_for_the_index() {
    // CT-29 (PERF-3)
    let corp = ExampleCorp::start().await;
    assert_eq!(corp.run(&["--json", "show", "INC0012345"]).code, 0);
    let queries = corp.queries_to("/api/now/table/sys_journal_field").await;
    assert!(!queries.is_empty());
    for q in queries {
        let decoded: String = url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "sysparm_query")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        assert!(
            decoded.starts_with("nameINincident,task^element_id="),
            "{decoded}"
        );
    }
}

#[tokio::test]
async fn hyphenated_ticket_numbers_resolve_and_keep_their_separator() {
    // CT-33 (ID-2)
    let corp = ExampleCorp::start().await;
    let out = corp.run(&["--json", "show", "abc-1234567"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.json()["table"], "u_abc_request");
    let sent: Vec<String> = corp
        .queries_to("/api/now/table/u_abc_request")
        .await
        .iter()
        .filter_map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "sysparm_query")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    assert!(sent.iter().any(|q| q == "number=ABC-1234567"), "{sent:?}");
}

#[tokio::test]
async fn open_applies_the_packs_rule_and_reports_it() {
    // CT-36 (e2e)
    let corp = ExampleCorp::start().await;
    let out = corp.run(&["--json", "list", "--table", "incident", "--open"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let env = out.json();
    assert!(
        env["query"]
            .as_str()
            .unwrap_or_default()
            .contains("active=true^stateNOT IN6,7,8"),
        "{}",
        env["query"]
    );
    assert_eq!(env["open_rules"][0]["workaround"], true);

    let literal = corp.run(&["-o", "md", "list", "--table", "incident", "--active"]);
    assert!(
        literal.stdout.contains("--active is literal active=true"),
        "{}",
        literal.stdout
    );
}

#[tokio::test]
async fn list_group_filters_expand_through_the_suffix_convention() {
    // CT-16, CT-67 (Q-5)
    let corp = ExampleCorp::start().await;
    let out = corp.run(&[
        "--json", "list", "--table", "incident", "--group", "Network",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let q = out.json()["query"].as_str().unwrap_or_default().to_string();
    assert!(
        q.contains("assignment_group.nameINNetwork,Network - L2,Network - L3"),
        "{q}"
    );

    let md = corp.run(&[
        "-o",
        "md",
        "list",
        "--table",
        "incident",
        "--assignment-group",
        "Network",
    ]);
    assert!(
        md.stdout
            .contains("group: Network → Network, Network - L2, Network - L3 (suffix expansion)"),
        "{}",
        md.stdout
    );

    let comma = corp.run(&[
        "--json",
        "list",
        "--table",
        "incident",
        "--group",
        "Ops, EMEA",
    ]);
    assert_eq!(comma.code, 0, "{}", comma.stderr);
    let q = comma.json()["query"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        q.contains("assignment_group.name=Ops, EMEA^ORassignment_group.name=Ops, EMEA - L2^ORassignment_group.name=Ops, EMEA - L3"),
        "{q}"
    );
}

#[tokio::test]
async fn in_use_values_verify_what_they_can_and_never_prove_absence() {
    // CT-08, CT-08c (rows 5, 8; DISC-2, DISC-3)
    let corp = ExampleCorp::start_without_pack().await;
    corp.mount(support::Scenario::InUseRenumbered).await;
    let first = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(first.code, 8, "{}", first.stderr);
    let f = &first.json()["unverifiable_fields"][0];
    assert_eq!(f["reason"], "ootb_unconfirmed");
    assert_eq!(f["would_send"], "low");
    assert_eq!(f["suggested"], "5");
    let stats = corp.queries_to("/api/now/stats/incident").await.len();
    assert_eq!(stats, 1);
    let cached = std::fs::read_to_string(corp.cache_file("discovered/incident.json"))
        .expect("discovered cache");
    assert!(cached.contains("\"complete\": false"), "{cached}");

    let again = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(again.code, 8, "{}", again.stderr);
    assert_eq!(again.json()["unverifiable_fields"][0], *f);
    assert_eq!(
        corp.queries_to("/api/now/stats/incident").await.len(),
        stats,
        "a re-run inside the TTL sends no stats request"
    );

    let five = corp.run(&["--json", "update", "INC0012345", "--priority", "5 - Low"]);
    assert_eq!(five.code, 0, "{}", five.stderr);
    assert_eq!(five.json()["diffs"][0]["source"], "discovered");
    assert_eq!(five.json()["diffs"][0]["status"], "verified (in-use set)");
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn an_in_use_set_confirms_an_ootb_alias() {
    // CT-08b (row 6)
    let corp = ExampleCorp::start_without_pack().await;
    corp.mount(support::Scenario::InUseOotbLow).await;
    let out = corp.run(&["--json", "update", "INC0012345", "--priority", "low"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let diff = &out.json()["diffs"][0];
    assert_eq!(diff["after_value"], "4");
    assert_eq!(diff["source"], "ootb");
}

#[tokio::test]
async fn unauthorized_stats_leave_no_metadata_and_are_remembered() {
    // CT-08d (row 7)
    let corp = ExampleCorp::start_without_pack().await;
    corp.mount(support::Scenario::StatsUnauthorized).await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--priority",
        "low",
        "--write",
    ]);
    assert_eq!(out.code, 8, "{}", out.stderr);
    assert_eq!(
        out.json()["unverifiable_fields"][0]["reason"],
        "no_metadata"
    );
    let caps = std::fs::read_to_string(corp.cache_file("capabilities.json")).expect("caps");
    assert!(caps.contains("stats_group_by"), "{caps}");
    let again = corp.run(&["--json", "update", "INC0012345", "--priority", "low"]);
    assert_eq!(again.code, 8);
    assert_eq!(corp.queries_to("/api/now/stats/incident").await.len(), 1);
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn a_value_not_in_the_in_use_set_is_not_seen_and_blocks_the_write() {
    // CT-10b
    let pack = support::EXAMPLE_PACK.replace(
        "choice_fields = { incident = [\"priority\", \"state\"]",
        "choice_fields = { incident = [\"priority\", \"state\", \"u_tier\"]",
    );
    let corp = ExampleCorp::start_with_pack(&pack).await;
    corp.mount(support::Scenario::InUseRenumbered).await;
    corp.mount_incident_patch(serde_json::json!({})).await;
    let out = corp.run(&[
        "--json",
        "update",
        "INC0012345",
        "--set",
        "u_tier=gold",
        "--write",
    ]);
    assert_eq!(out.code, 8, "{}", out.stderr);
    let f = &out.json()["unverifiable_fields"][0];
    assert_eq!(f["reason"], "not_seen");
    let candidates = f["candidates"].to_string();
    assert!(
        candidates.contains("silver") && candidates.contains("bronze"),
        "{candidates}"
    );
    assert!(corp.patch_bodies().await.is_empty(), "zero PATCH");
}

/// Every fixture string that `discover` must never persist (NA-8).
const FIXTURE_SECRETS: &[&str] = &[
    "11111111111111111111111111111111",
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
    "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    "33333333333333333333333333333333",
    "44444444444444444444444444444444",
    "55555555555555555555555555555555",
    "pat.example",
    "Pat Example",
    "Network - L2",
    "Storage - L2",
    "Ops, EMEA",
    "Database - L3",
    "VPN drops",
    "Badge access",
];

fn assert_no_fixture_secrets(label: &str, text: &str) {
    for s in FIXTURE_SECRETS {
        assert!(!text.contains(s), "{label} leaks {s:?}:\n{text}");
    }
}

#[tokio::test]
async fn discover_writes_a_private_draft_with_metadata_only() {
    // CT-35, CT-30a (DISC-4, DISC-5; NA-1, NA-8)
    let pack = support::EXAMPLE_PACK.replace(
        "choice_fields = { incident = [\"priority\", \"state\"]",
        "choice_fields = { incident = [\"priority\", \"state\", \"assigned_to\"]",
    );
    let corp = ExampleCorp::start_with_pack(&pack).await;
    corp.mount(support::Scenario::InUseRenumbered).await;
    corp.mount(support::Scenario::TaskSample).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let draft_path = out_dir.path().join("draft.pack.toml");
    let draft_arg = draft_path.to_str().expect("utf-8 path");

    let run = corp.run(&["discover", "--out", draft_arg]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("Wrote draft pack:"), "{}", run.stdout);
    assert!(run.stdout.contains("Next: 1)"), "{}", run.stdout);

    let draft = std::fs::read_to_string(&draft_path).expect("draft");
    assert!(
        draft.starts_with("# Contains instance metadata. Do not commit to a public repository.")
    );
    assert!(draft.contains("status = \"draft\""), "{draft}");
    assert!(draft.contains("ABC = \"u_abc_request\""), "{draft}");
    assert!(
        draft.contains("3 of the 5 most recent task rows use prefix ABC"),
        "{draft}"
    );
    assert!(draft.contains("[choices.incident.priority]"), "{draft}");
    for v in 0..=5 {
        assert!(
            draft.contains(&format!("{{ value = \"{v}\"")),
            "priority {v}: {draft}"
        );
    }
    assert!(draft.contains("# in-use values only (6 seen)"), "{draft}");
    assert!(
        draft.contains("suffixes = [\" - L2\", \" - L3\"]"),
        "{draft}"
    );
    assert!(draft.contains("# skipped: incident.assigned_to"), "{draft}");
    assert!(
        draft.contains("# custom field: u_abc_request.u_tier (choice-typed)"),
        "{draft}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&draft_path)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    assert_no_fixture_secrets("draft", &draft);
    assert_no_fixture_secrets(
        "capabilities.json",
        &std::fs::read_to_string(corp.cache_file("capabilities.json")).expect("caps"),
    );
    for entry in std::fs::read_dir(corp.cache_file("schemas")).expect("schemas dir") {
        let p = entry.expect("entry").path();
        assert_no_fixture_secrets(
            &p.display().to_string(),
            &std::fs::read_to_string(&p).expect("schema"),
        );
    }

    let validated = corp.run(&["pack", "validate", draft_arg]);
    assert_eq!(
        validated.code, 0,
        "{}{}",
        validated.stdout, validated.stderr
    );

    let again = corp.run(&["discover", "--out", draft_arg]);
    assert_eq!(again.code, 2, "refuses to overwrite: {}", again.stderr);
    let forced = corp.run(&["discover", "--out", draft_arg, "--force"]);
    assert_eq!(forced.code, 0, "{}", forced.stderr);

    assert!(
        corp.mutating_requests().await.is_empty(),
        "discover is read-only (NA-1)"
    );
}

#[tokio::test]
async fn discover_without_samples_reads_no_record_rows() {
    // CT-35 (--no-samples, BF-TEST-2f)
    let corp = ExampleCorp::start().await;
    corp.mount(support::Scenario::InUseRenumbered).await;
    corp.mount(support::Scenario::TaskSample).await;
    let out_dir = tempfile::tempdir().expect("tempdir");
    let draft_path = out_dir.path().join("draft.pack.toml");
    let run = corp.run(&[
        "discover",
        "--no-samples",
        "--out",
        draft_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let draft = std::fs::read_to_string(&draft_path).expect("draft");
    assert!(
        draft.contains("# prefixes: none discovered (sys_number unreadable, --no-samples set)"),
        "{draft}"
    );
    assert!(
        draft.contains("[choices.incident.priority]"),
        "choice labels are metadata: {draft}"
    );
    for p in [
        "/api/now/table/task",
        "/api/now/table/sys_user_group",
        "/api/now/table/incident",
    ] {
        assert!(corp.queries_to(p).await.is_empty(), "{p} was read");
    }
    assert!(corp.mutating_requests().await.is_empty());
}

#[tokio::test]
async fn approvals_list_includes_group_linked_rows_once() {
    // CT-37 (APR-1, APR-2, BF-TEST-2e)
    let corp = ExampleCorp::start().await;
    corp.mount(support::Scenario::LinkedApprovals).await;
    let out = corp.run(&["--json", "approvals", "list"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let env = out.json();
    let items = env["items"].as_array().expect("items");
    let linked: Vec<(String, String)> = items
        .iter()
        .map(|i| {
            (
                i["sys_id"].as_str().unwrap_or_default().to_string(),
                i["linked_by"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        linked,
        vec![
            (
                "aa000000000000000000000000000003".to_string(),
                "group".to_string()
            ),
            (
                "aa000000000000000000000000000002".to_string(),
                "both".to_string()
            ),
            (
                "aa000000000000000000000000000001".to_string(),
                "user".to_string()
            ),
        ],
        "newest first, each row once"
    );
    assert_eq!(items[0]["group"], "Network - L2 approvers");
    let queries = corp.queries_to("/api/now/table/sysapproval_approver").await;
    assert_eq!(queries.len(), 2, "{queries:?}");
    assert!(
        queries
            .iter()
            .all(|q| q.contains("ORDERBYDESCsys_created_on")),
        "{queries:?}"
    );
    assert!(
        queries
            .iter()
            .any(|q| q.contains("group.assignment_groupIN33333333333333333333333333333333")),
        "{queries:?}"
    );

    let all = corp.run(&[
        "--json",
        "approvals",
        "list",
        "--all-users",
        "--state",
        "approved",
    ]);
    assert_eq!(all.code, 0, "{}", all.stderr);
    let q = all.json()["query"].as_str().unwrap_or_default().to_string();
    assert!(
        q.contains("state=approved") && !q.contains("approver="),
        "{q}"
    );
    assert!(all.json()["group_query"].is_null());
}

#[tokio::test]
async fn agent_comments_and_notes_carry_the_pack_marker() {
    // CT-38 (SAFE-8, NA-12): the harness runs with --no-interactive and a non-TTY stdin.
    let corp = ExampleCorp::start().await;
    let note = corp.run(&["--json", "note", "INC0012345", "Rebooted the VPN gateway"]);
    assert_eq!(note.code, 0, "{}", note.stderr);
    let diff = &note.json()["diffs"][0];
    assert_eq!(
        diff["after_value"],
        "[sncfr-agent] Rebooted the VPN gateway"
    );
    assert_eq!(diff["source"], "input + marker");

    let update = corp.run(&["--json", "update", "INC0012345", "--comment", "Fixed"]);
    assert_eq!(update.code, 0, "{}", update.stderr);
    assert_eq!(
        update.json()["diffs"][0]["after_value"],
        "[sncfr-agent] Fixed"
    );

    let code = corp.run(&["note", "INC0012345", "[code]<b>x</b>[/code]"]);
    assert_eq!(code.code, 2, "{}", code.stderr);
    let allowed = corp.run(&[
        "note",
        "INC0012345",
        "[code]<b>x</b>[/code]",
        "--allow-code-tag",
    ]);
    assert_eq!(allowed.code, 0, "{}", allowed.stderr);
    assert!(
        allowed.stderr.contains("[code]"),
        "warned: {}",
        allowed.stderr
    );
    assert!(corp.mutating_requests().await.is_empty());
}
