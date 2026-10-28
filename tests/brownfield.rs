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
