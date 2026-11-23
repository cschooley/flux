//! Golden files (examples/): every one parses, follows the flux rules, is
//! valid against the official SARIF 2.1.0 schema, and round-trips exactly.

use std::fs;
use std::path::PathBuf;

use flux::fingerprint::{dast_v1, sast_v1, DAST_V1, SAST_V1};
use flux::validate::validate;
use flux::{
    ArtifactContent, Finding, Location, Report, Rule, Status, Suppression, Taxon, ToolComponent,
    WebRequest, WebResponse,
};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sarif_schema() -> jsonschema::Validator {
    let text = fs::read_to_string(root().join("schema/sarif-schema-2.1.0.json")).unwrap();
    jsonschema::draft4::new(&serde_json::from_str::<Value>(&text).unwrap()).unwrap()
}

fn schema_errors(v: &Value) -> Vec<String> {
    sarif_schema()
        .iter_errors(v)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect()
}

fn examples() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(root().join("examples"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sarif"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn there_is_an_example_for_each_flow() {
    let names: Vec<String> = examples().into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        names,
        [
            "dast-candidate.sarif",
            "dast-confirms-sast.sarif",
            "retest.sarif",
            "sast-suspected.sarif",
            "suppressed-duplicate.sarif"
        ]
    );
}

#[test]
fn examples_are_valid_sarif() {
    for (name, text) in examples() {
        let errs = schema_errors(&serde_json::from_str(&text).unwrap());
        assert!(errs.is_empty(), "{name}: {errs:#?}");
    }
}

#[test]
fn examples_follow_the_flux_rules() {
    for (name, text) in examples() {
        let problems = validate(&Report::from_json(&text).unwrap());
        assert!(problems.is_empty(), "{name}: {problems:#?}");
    }
}

#[test]
fn examples_round_trip_exactly() {
    for (name, text) in examples() {
        let report = Report::from_json(&text).unwrap();
        let again: Value = serde_json::from_str(&report.to_json_pretty().unwrap()).unwrap();
        assert_eq!(
            again,
            serde_json::from_str::<Value>(&text).unwrap(),
            "{name}"
        );
        assert_eq!(
            Report::from_json(&again.to_string()).unwrap(),
            report,
            "{name}"
        );
    }
}

#[test]
fn example_fingerprints_are_what_the_crate_computes() {
    let get = |name: &str| {
        Report::from_json(&fs::read_to_string(root().join("examples").join(name)).unwrap()).unwrap()
    };
    let cand = get("dast-candidate.sarif");
    let f = cand.findings().next().unwrap();
    assert_eq!(
        f.endpoint(),
        Some(("GET", "https://shop.example/api/products/17"))
    );
    assert_eq!(
        f.fingerprints[DAST_V1],
        dast_v1(
            "shop.example",
            "GET",
            "/api/products/17",
            Some("sort"),
            &f.rule_id
        )
    );
    let sast = get("sast-suspected.sarif");
    let s = sast.findings().next().unwrap();
    assert_eq!(
        s.fingerprints[SAST_V1],
        sast_v1(
            "cschooley/shop",
            "src/catalog.rs",
            "list_products",
            &s.rule_id
        )
    );
    let retest = get("retest.sarif");
    let r = retest.findings().next().unwrap();
    assert_eq!(
        r.fingerprints[DAST_V1],
        dast_v1("shop.example", "GET", "/api/orders/1001", None, &r.rule_id)
    );
    assert_eq!(r.status(), Some(Status::Fixed));
    let dup = get("suppressed-duplicate.sarif");
    let originals: Vec<&Finding> = dup.findings().collect();
    assert!(!originals[0].is_suppressed());
    assert_eq!(
        originals[1].duplicate_of(),
        originals[0].correlation_guid.as_deref()
    );
}

// What a producer builds in code is valid SARIF and follows the rules too.
#[test]
fn a_report_built_in_code_is_valid() {
    let mut f = Finding::new("WSTG-INPV-05", "A quote in sort breaks the SQL query.");
    f.level = Some(flux::Level::Error);
    f.rank = Some(60.0);
    f.fingerprints.insert(
        DAST_V1.into(),
        dast_v1("a.test", "GET", "/p/1", Some("sort"), "WSTG-INPV-05"),
    );
    f.locations
        .push(Location::endpoint("GET", "https://a.test/p/1?sort=x'"));
    f.taxa.push(Taxon::cwe(89));
    f.web_request = Some(WebRequest {
        method: Some("GET".into()),
        target: Some("https://a.test/p/1?sort=x'".into()),
        ..Default::default()
    });
    f.web_response = Some(WebResponse {
        status_code: Some(500),
        body: Some(ArtifactContent::text("SQLSTATE 42601")),
        ..Default::default()
    });
    f.properties.status = Some(Status::Candidate);
    f.properties.replay_ids = vec!["ex-1".into()];
    f.suppressions.push(Suppression::duplicate_of(
        "3b0c8f0e-6a52-4c1e-9d0a-2f6a1b7c9e41",
        "same builder",
    ));
    let mut driver = ToolComponent::tool("spall", "0.4.0");
    driver
        .rules
        .push(Rule::new("WSTG-INPV-05", "Testing for SQL Injection").with_cwe(89));
    let report = Report::new(driver, vec![f]);

    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(schema_errors(&v), Vec::<String>::new());
    assert_eq!(validate(&report), vec![]);
}

// The schema check is real: it rejects what SARIF doesn't allow.
#[test]
fn the_schema_check_catches_bad_sarif() {
    let (_, text) = examples().into_iter().next().unwrap();
    let mut v: Value = serde_json::from_str(&text).unwrap();
    v["runs"][0]["results"][0]["level"] = "high".into();
    assert!(!schema_errors(&v).is_empty());
}
