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
