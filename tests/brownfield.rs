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
