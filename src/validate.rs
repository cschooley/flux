//! The flux rules a document must follow beyond SARIF's own schema
//! (SPEC.md). SARIF schema validation itself is in the tests, against the
//! vendored official schema; this checks what the schema can't.

use std::collections::HashSet;
use std::fmt;

use crate::finding::{Disposition, Finding};
use crate::fingerprint::{DAST_V1, SAST_V1};
use crate::report::{Report, Run, SARIF_VERSION};

/// One broken rule, with where it is (`runs[0].results[2].fingerprints`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub at: String,
    pub what: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.what)
    }
}

/// Parse `text` as a flux document and check it. A parse error means it
/// isn't SARIF-shaped at all.
pub fn validate_json(text: &str) -> Result<Vec<Problem>, serde_json::Error> {
    Ok(validate(&Report::from_json(text)?))
}

/// Every flux rule `report` breaks; empty when it follows the profile.
pub fn validate(report: &Report) -> Vec<Problem> {
    let mut out = Vec::new();
    let mut bad = |at: String, what: &str| {
        out.push(Problem {
            at,
            what: what.to_owned(),
        })
    };
    if report.version != SARIF_VERSION {
        bad("version".into(), "must be \"2.1.0\"");
    }
    for (ri, run) in report.runs.iter().enumerate() {
        let at = format!("runs[{ri}]");
        if run.tool.driver.name.is_empty() {
            bad(format!("{at}.tool.driver.name"), "is required");
        }
        let mut ids = HashSet::new();
        for (i, rule) in run.tool.driver.rules.iter().enumerate() {
            if rule.id.is_empty() {
                bad(format!("{at}.tool.driver.rules[{i}].id"), "is required");
            } else if !ids.insert(rule.id.as_str()) {
                bad(format!("{at}.tool.driver.rules[{i}].id"), "is not unique");
            }
        }
        for (fi, f) in run.results.iter().enumerate() {
            finding(run, f, &format!("{at}.results[{fi}]"), &mut bad);
        }
    }
    out
}

fn finding(run: &Run, f: &Finding, at: &str, bad: &mut impl FnMut(String, &str)) {
    if f.rule_id.is_empty() {
        bad(format!("{at}.ruleId"), "is required");
    }
    if f.message.text.trim().is_empty() {
        bad(format!("{at}.message.text"), "is required");
    }
    if let Some(r) = f.rank {
        if !(0.0..=100.0).contains(&r) {
            bad(format!("{at}.rank"), "must be 0-100");
        }
    }
    if !f.fingerprints.keys().any(|k| k.starts_with("flux/")) {
        bad(format!("{at}.fingerprints"), "needs at least one flux/ key");
    }
    for key in [DAST_V1, SAST_V1] {
        if let Some(v) = f.fingerprints.get(key) {
            if !is_sha256_hex(v) {
                bad(
                    format!("{at}.fingerprints[\"{key}\"]"),
                    "must be a lowercase hex SHA-256",
                );
            }
        }
    }
    if let Some(g) = &f.correlation_guid {
        if !is_guid(g) {
            bad(format!("{at}.correlationGuid"), "must be a GUID");
        }
    }
    if let Some(g) = &f.properties.hypothesis_for {
        if !is_guid(g) {
            bad(
                format!("{at}.properties[\"flux/hypothesisFor\"]"),
                "must be a GUID",
            );
        }
    }
    for (ti, t) in f.taxa.iter().enumerate() {
        match t.taxonomy() {
            Some(name) if !run.declares_taxonomy(name) => {
                bad(
                    format!("{at}.taxa[{ti}]"),
                    "refers to a taxonomy the run doesn't declare",
                );
            }
            Some(crate::finding::CWE) if t.cwe_id().is_none() => {
                bad(format!("{at}.taxa[{ti}].id"), "a CWE id is a number");
            }
            _ => {}
        }
    }
    for (si, s) in f.suppressions.iter().enumerate() {
        let sat = format!("{at}.suppressions[{si}]");
        let why = s.justification.as_deref().unwrap_or("");
        if why.trim().is_empty() {
            bad(format!("{sat}.justification"), "is required");
        }
        if s.properties.disposition == Some(Disposition::Duplicate) {
            match s.properties.duplicate_of.as_deref() {
                Some(g) if is_guid(g) => {
                    if !why.contains(g) {
                        bad(
                            format!("{sat}.justification"),
                            "a duplicate's justification names the original's correlationGuid",
                        );
                    }
                }
                _ => bad(
                    format!("{sat}.properties[\"flux/duplicateOf\"]"),
                    "a duplicate needs the original's correlationGuid",
                ),
            }
        }
    }
    for (li, l) in f.locations.iter().enumerate() {
        if let Some((_, uri)) = l.endpoint_parts() {
            if uri.contains(['?', '#']) {
                bad(
                    format!("{at}.locations[{li}]"),
                    "an endpoint URL has no query string or fragment",
                );
            }
        }
    }
    if f.web_request.is_some() && f.endpoint().is_none() {
        bad(
            format!("{at}.locations"),
            "DAST evidence needs an endpoint location",
        );
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// SARIF's GUID pattern: 8-4-4-4-12 hex digits.
fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::dast_v1;
    use crate::{Finding, Location, Suppression, Taxon, ToolComponent};

    const G: &str = "6f1c2e3a-0000-4000-8000-000000000001";

    fn good() -> Finding {
        let mut f = Finding::new("WSTG-INPV-05", "SQL injection in id");
        f.fingerprints.insert(
            DAST_V1.into(),
            dast_v1("a.test", "GET", "/u/1", Some("id"), "WSTG-INPV-05"),
        );
        f.locations
            .push(Location::endpoint("GET", "https://a.test/u/1?id=1"));
        f
    }

    fn problems(f: Finding) -> Vec<String> {
        validate(&Report::new(ToolComponent::tool("spall", "0.4.0"), vec![f]))
            .into_iter()
            .map(|p| p.to_string())
            .collect()
    }

    #[test]
    fn a_good_finding_passes() {
        assert_eq!(problems(good()), Vec::<String>::new());
    }

    #[test]
    fn required_fields() {
        let mut f = good();
        f.rule_id.clear();
        f.message.text = " ".into();
        f.fingerprints.clear();
        assert_eq!(
            problems(f),
            vec![
                "runs[0].results[0].ruleId: is required",
                "runs[0].results[0].message.text: is required",
                "runs[0].results[0].fingerprints: needs at least one flux/ key",
            ]
        );
    }

    #[test]
    fn values_are_checked() {
        let mut f = good();
        f.rank = Some(101.0);
        f.fingerprints.insert(DAST_V1.into(), "ABC".into());
        f.correlation_guid = Some("nope".into());
        f.properties.hypothesis_for = Some("nope".into());
        f.locations
            .push(Location::endpoint("GET", "https://a.test/x"));
        f.locations[1]
            .physical_location
            .as_mut()
            .unwrap()
            .artifact_location
            .uri = "https://a.test/x?q=1".into();
        assert_eq!(
            problems(f),
            vec![
                "runs[0].results[0].rank: must be 0-100",
                "runs[0].results[0].fingerprints[\"flux/dast/v1\"]: must be a lowercase hex SHA-256",
                "runs[0].results[0].correlationGuid: must be a GUID",
                "runs[0].results[0].properties[\"flux/hypothesisFor\"]: must be a GUID",
                "runs[0].results[0].locations[1]: an endpoint URL has no query string or fragment",
            ]
        );
    }

    #[test]
    fn taxa_need_their_taxonomy() {
        let mut f = good();
        f.taxa.push(Taxon::cwe(89));
        assert!(problems(f.clone()).is_empty(), "Report::new declares CWE");
        let mut r = Report::new(ToolComponent::tool("spall", "0.4.0"), vec![f]);
        r.runs[0].taxonomies.clear();
        r.runs[0].results[0].taxa.push(Taxon {
            id: "x".into(),
            ..Taxon::cwe(1)
        });
        let got: Vec<String> = validate(&r).into_iter().map(|p| p.to_string()).collect();
        assert_eq!(
            got,
            vec![
                "runs[0].results[0].taxa[0]: refers to a taxonomy the run doesn't declare",
                "runs[0].results[0].taxa[1]: refers to a taxonomy the run doesn't declare",
            ]
        );
        r.runs[0].taxonomies.push(ToolComponent::cwe());
        let got: Vec<String> = validate(&r).into_iter().map(|p| p.to_string()).collect();
        assert_eq!(
            got,
            vec!["runs[0].results[0].taxa[1].id: a CWE id is a number"]
        );
    }

    #[test]
    fn suppressions_need_justification_and_duplicates_their_original() {
        let mut f = good();
        f.suppressions.push(Suppression::false_positive(""));
        f.suppressions.push(Suppression::duplicate_of(G, "same"));
        let mut d = Suppression::duplicate_of(G, "same");
        d.justification = Some("same".into());
        f.suppressions.push(d);
        let mut d = Suppression::duplicate_of(G, "same");
        d.properties.duplicate_of = None;
        f.suppressions.push(d);
        assert_eq!(
            problems(f),
            vec![
                "runs[0].results[0].suppressions[0].justification: is required",
                "runs[0].results[0].suppressions[2].justification: a duplicate's justification names the original's correlationGuid",
                "runs[0].results[0].suppressions[3].properties[\"flux/duplicateOf\"]: a duplicate needs the original's correlationGuid",
            ]
        );
    }

    #[test]
    fn dast_evidence_needs_an_endpoint() {
        let mut f = good();
        f.locations.clear();
        f.web_request = Some(Default::default());
        assert_eq!(
            problems(f),
            vec!["runs[0].results[0].locations: DAST evidence needs an endpoint location"]
        );
    }

    #[test]
    fn report_level_rules() {
        let mut driver = ToolComponent::tool("", "1");
        driver.rules = vec![
            crate::Rule::new("a", "x"),
            crate::Rule::new("a", "y"),
            crate::Rule::new("", "z"),
        ];
        let mut r = Report::new(driver, vec![]);
        r.version = "2.0.0".into();
        let got: Vec<String> = validate(&r).into_iter().map(|p| p.to_string()).collect();
        assert_eq!(
            got,
            vec![
                "version: must be \"2.1.0\"",
                "runs[0].tool.driver.name: is required",
                "runs[0].tool.driver.rules[1].id: is not unique",
                "runs[0].tool.driver.rules[2].id: is required",
            ]
        );
    }

    #[test]
    fn validate_json_parses_first() {
        assert!(validate_json("not json").is_err());
        assert_eq!(
            validate_json(r#"{"version":"2.1.0","runs":[]}"#).unwrap(),
            vec![]
        );
    }
}
