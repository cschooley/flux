//! `Finding`: one SARIF `result` under the flux profile (SPEC.md, "Field
//! mapping"). Standard SARIF fields are typed fields with their SARIF names;
//! flux's own data is typed too, under `properties` ("flux/..." keys).
//! Anything else a SARIF producer wrote is kept in `extra`, so reading and
//! writing a document loses nothing.

use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::fingerprint::strip_query;

/// SARIF fields this crate doesn't model, kept as they were.
pub type Extra = Map<String, Value>;

/// Severity: SARIF `result.level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    None,
    Note,
    Warning,
    Error,
}

/// Verification state, `flux/status`: is the issue real? Orthogonal to
/// suppression, which is what a human decided to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Candidate,
    Suspected,
    Confirmed,
    Fixed,
}

/// Run-over-run diff, SARIF `result.baselineState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BaselineState {
    New,
    Unchanged,
    Updated,
    Absent,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(default)]
    pub text: String,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Message {
    pub fn new(text: impl Into<String>) -> Self {
        Message {
            text: text.into(),
            extra: Extra::new(),
        }
    }
}

/// One finding: a SARIF `result`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Vuln class; stable per tool. Required by flux (an empty one fails
    /// validation rather than parsing, so a bad document can be reported).
    #[serde(default)]
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    #[serde(default)]
    pub message: Message,
    /// Tool-reported confidence, 0-100.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "rank_out"
    )]
    pub rank: Option<f64>,
    /// Dedup keys; at least one `flux/...` key (see `fingerprint`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fingerprints: BTreeMap<String, String>,
    /// Same issue across runs: assigned on first confirmation, then kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<BaselineState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    /// A SAST location on a DAST-confirmed finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<Location>,
    /// CWE / CAPEC references (`Taxon::cwe`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxa: Vec<Taxon>,
    /// Triage decisions: false positive, accepted risk, duplicate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<Suppression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub work_item_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// The decisive request (DAST evidence); the rest go in `replay_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_request: Option<WebRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_response: Option<WebResponse>,
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Finding {
    pub fn new(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        Finding {
            rule_id: rule_id.into(),
            message: Message::new(message),
            ..Default::default()
        }
    }

    pub fn status(&self) -> Option<Status> {
        self.properties.status
    }

    /// Suppressed by any suppression in effect (`accepted`, or no status:
    /// SARIF treats an absent status as accepted).
    pub fn is_suppressed(&self) -> bool {
        self.suppressions.iter().any(Suppression::in_effect)
    }

    /// The `correlationGuid` this finding duplicates, if a suppression in
    /// effect says so.
    pub fn duplicate_of(&self) -> Option<&str> {
        self.suppressions
            .iter()
            .filter(|s| s.in_effect() && s.properties.disposition == Some(Disposition::Duplicate))
            .find_map(|s| s.properties.duplicate_of.as_deref())
    }

    /// The DAST endpoint (method, URL) from the first location that has one.
    pub fn endpoint(&self) -> Option<(&str, &str)> {
        self.locations.iter().find_map(Location::endpoint_parts)
    }

    /// The CWE ids among `taxa`.
    pub fn cwes(&self) -> Vec<u32> {
        self.taxa.iter().filter_map(Taxon::cwe_id).collect()
    }
}

// SARIF's `rank` is a number; write a whole one as an integer (70, not 70.0)
// so documents round-trip as written.
fn rank_out<S: Serializer>(rank: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match rank {
        Some(r) if r.fract() == 0.0 && r.abs() < 1e15 => s.serialize_i64(*r as i64),
        Some(r) => s.serialize_f64(*r),
        None => s.serialize_none(),
    }
}

/// The `flux/` property bag on a result. SARIF's own `tags` is here too
/// (it lives in every property bag).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Properties {
    #[serde(
        rename = "flux/status",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status: Option<Status>,
    /// Tools that confirmed it, e.g. `["scurf", "spall"]`.
    #[serde(
        rename = "flux/confirmedBy",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub confirmed_by: Vec<String>,
    /// taphttp exchange ids (captured and replayed) backing the evidence.
    #[serde(
        rename = "flux/replayIds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub replay_ids: Vec<String>,
    #[serde(
        rename = "flux/redacted",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub redacted: Option<bool>,
    /// On spall output: the `correlationGuid` of the ingested finding tested.
    #[serde(
        rename = "flux/hypothesisFor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hypothesis_for: Option<String>,
    #[serde(
        rename = "flux/fingerprintVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint_version: Option<String>,
    #[serde(
        rename = "flux/traceId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Properties {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A SARIF `location`: a file region (SAST) or an endpoint (DAST).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<PhysicalLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logical_locations: Vec<LogicalLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `logicalLocation.kind` marking the HTTP method of a DAST endpoint.
pub const HTTP_METHOD_KIND: &str = "httpMethod";

impl Location {
    /// A DAST endpoint: the URL without its query or fragment as the
    /// artifact, the method (uppercased) as a logical location.
    pub fn endpoint(method: &str, url: &str) -> Self {
        Location {
            physical_location: Some(PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: strip_query(url).to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            logical_locations: vec![LogicalLocation {
                name: Some(method.to_ascii_uppercase()),
                kind: Some(HTTP_METHOD_KIND.into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// A SAST location: a file, optionally from a start line.
    pub fn file(path: &str, start_line: Option<u64>) -> Self {
        Location {
            physical_location: Some(PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: path.to_owned(),
                    ..Default::default()
                },
                region: start_line.map(|l| Region {
                    start_line: Some(l),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// (method, URL) when this is a DAST endpoint.
    pub fn endpoint_parts(&self) -> Option<(&str, &str)> {
        let method = self
            .logical_locations
            .iter()
            .find(|l| l.kind.as_deref() == Some(HTTP_METHOD_KIND))?
            .name
            .as_deref()?;
        let uri = self
            .physical_location
            .as_ref()?
            .artifact_location
            .uri
            .as_str();
        Some((method, uri))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    #[serde(default)]
    pub artifact_location: ArtifactLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactLocation {
    #[serde(default)]
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A reference into a taxonomy (SARIF `reportingDescriptorReference`),
/// e.g. CWE-89 is `{"id": "89", "toolComponent": {"name": "CWE"}}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Taxon {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_component: Option<ComponentRef>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The taxonomy name flux uses for CWE.
pub const CWE: &str = "CWE";

impl Taxon {
    pub fn cwe(id: u32) -> Self {
        Taxon {
            id: id.to_string(),
            tool_component: Some(ComponentRef {
                name: Some(CWE.into()),
                extra: Extra::new(),
            }),
            extra: Extra::new(),
        }
    }

    pub fn taxonomy(&self) -> Option<&str> {
        self.tool_component.as_ref()?.name.as_deref()
    }

    pub fn cwe_id(&self) -> Option<u32> {
        (self.taxonomy() == Some(CWE))
            .then(|| self.id.parse().ok())
            .flatten()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComponentRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SuppressionKind {
    InSource,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SuppressionStatus {
    Accepted,
    UnderReview,
    Rejected,
}

/// Why a human suppressed a finding: `flux/disposition` on the suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    /// Not a real issue (triage: reject).
    FalsePositive,
    AcceptedRisk,
    /// The same issue as another finding (`flux/duplicateOf`).
    Duplicate,
}

/// A triage decision: SARIF `suppression`, with a required justification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suppression {
    pub kind: SuppressionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SuppressionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    #[serde(default, skip_serializing_if = "SuppressionProperties::is_empty")]
    pub properties: SuppressionProperties,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SuppressionProperties {
    #[serde(
        rename = "flux/disposition",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<Disposition>,
    /// For a duplicate: the original's `correlationGuid`.
    #[serde(
        rename = "flux/duplicateOf",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duplicate_of: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl SuppressionProperties {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl Suppression {
    fn decided(disposition: Disposition, justification: String) -> Self {
        Suppression {
            kind: SuppressionKind::External,
            status: Some(SuppressionStatus::Accepted),
            justification: Some(justification),
            guid: None,
            properties: SuppressionProperties {
                disposition: Some(disposition),
                ..Default::default()
            },
            extra: Extra::new(),
        }
    }

    pub fn false_positive(justification: impl Into<String>) -> Self {
        Self::decided(Disposition::FalsePositive, justification.into())
    }

    pub fn accepted_risk(justification: impl Into<String>) -> Self {
        Self::decided(Disposition::AcceptedRisk, justification.into())
    }

    /// A duplicate of the finding with `correlationGuid` `original`. The
    /// justification names the original too (SPEC.md, "Field mapping").
    pub fn duplicate_of(original: &str, justification: impl Into<String>) -> Self {
        let why = justification.into();
        let text = if why.contains(original) {
            why
        } else {
            format!("duplicate of {original}: {why}")
        };
        let mut s = Self::decided(Disposition::Duplicate, text);
        s.properties.duplicate_of = Some(original.to_owned());
        s
    }

    /// In effect: accepted, or no status (SARIF's default).
    pub fn in_effect(&self) -> bool {
        matches!(self.status, None | Some(SuppressionStatus::Accepted))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// RFC 3339, UTC (SARIF `date-time`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_detection_time_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_detection_time_utc: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// SARIF `webRequest`. SARIF's `headers` is an object, so a repeated
/// header name has one entry; how a producer joins repeats is its choice.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<ArtifactContent>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_phrase: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<ArtifactContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_response_received: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A body: `text`, or `binary` (base64).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ArtifactContent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl ArtifactContent {
    pub fn text(s: impl Into<String>) -> Self {
        ArtifactContent {
            text: Some(s.into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_minimal_finding_is_sarif_shaped() {
        let f = Finding::new("WSTG-INPV-05", "SQL injection in id");
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            json!({"ruleId": "WSTG-INPV-05", "message": {"text": "SQL injection in id"}})
        );
    }

    #[test]
    fn flux_properties_use_their_keys() {
        let mut f = Finding::new("r", "m");
        f.properties.status = Some(Status::Candidate);
        f.properties.replay_ids = vec!["e1".into()];
        f.properties.redacted = Some(true);
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(
            v["properties"],
            json!({"flux/status": "candidate", "flux/replayIds": ["e1"], "flux/redacted": true})
        );
        assert_eq!(serde_json::from_value::<Finding>(v).unwrap(), f);
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let v = json!({
            "ruleId": "r", "message": {"text": "m", "markdown": "*m*"},
            "kind": "fail", "codeFlows": [{"threadFlows": []}],
            "properties": {"flux/status": "suspected", "acme/x": 1},
            "locations": [{"id": 3, "physicalLocation": {"artifactLocation": {"uri": "a.rs", "index": 0}}}]
        });
        let f: Finding = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(f.status(), Some(Status::Suspected));
        assert_eq!(serde_json::to_value(&f).unwrap(), v);
    }

    #[test]
    fn rank_is_written_as_given() {
        let mut f = Finding::new("r", "m");
        f.rank = Some(70.0);
        assert_eq!(serde_json::to_value(&f).unwrap()["rank"], json!(70));
        f.rank = Some(72.5);
        assert_eq!(serde_json::to_value(&f).unwrap()["rank"], json!(72.5));
    }

    #[test]
    fn a_missing_rule_id_parses_so_validation_can_report_it() {
        let f: Finding = serde_json::from_value(json!({"message": {"text": "m"}})).unwrap();
        assert_eq!(f.rule_id, "");
    }

    #[test]
    fn an_endpoint_drops_the_query_and_uppercases_the_method() {
        let l = Location::endpoint("post", "https://a.test/api/users/7?token=abc#frag");
        assert_eq!(
            l.endpoint_parts(),
            Some(("POST", "https://a.test/api/users/7"))
        );
        assert_eq!(
            serde_json::to_value(&l).unwrap(),
            json!({
                "physicalLocation": {"artifactLocation": {"uri": "https://a.test/api/users/7"}},
                "logicalLocations": [{"name": "POST", "kind": "httpMethod"}]
            })
        );
        assert_eq!(Location::file("src/a.rs", Some(3)).endpoint_parts(), None);
    }

    #[test]
    fn cwe_taxa() {
        let mut f = Finding::new("r", "m");
        f.taxa = vec![
            Taxon::cwe(89),
            Taxon {
                id: "66".into(),
                ..Default::default()
            },
        ];
        assert_eq!(
            serde_json::to_value(&f.taxa[0]).unwrap(),
            json!({"id": "89", "toolComponent": {"name": "CWE"}})
        );
        assert_eq!(f.cwes(), vec![89]);
    }

    #[test]
    fn suppressions_carry_the_disposition() {
        let mut f = Finding::new("r", "m");
        assert!(!f.is_suppressed());
        f.suppressions
            .push(Suppression::false_positive("reflected but encoded"));
        assert!(f.is_suppressed());
        assert_eq!(
            serde_json::to_value(&f.suppressions[0]).unwrap(),
            json!({"kind": "external", "status": "accepted", "justification": "reflected but encoded",
                   "properties": {"flux/disposition": "falsePositive"}})
        );
    }

    #[test]
    fn a_duplicate_names_the_original_in_both_places() {
        let g = "6f1c2e3a-0000-4000-8000-000000000001";
        let s = Suppression::duplicate_of(g, "same parameter");
        assert_eq!(
            s.justification.as_deref(),
            Some(format!("duplicate of {g}: same parameter").as_str())
        );
        let mut f = Finding::new("r", "m");
        f.suppressions.push(s);
        assert_eq!(f.duplicate_of(), Some(g));
        // Not doubled when the justification already names it.
        assert_eq!(
            Suppression::duplicate_of(g, format!("see {g}"))
                .justification
                .as_deref(),
            Some(format!("see {g}").as_str())
        );
    }

    #[test]
    fn only_suppressions_in_effect_count() {
        let mut s = Suppression::false_positive("x");
        s.status = Some(SuppressionStatus::UnderReview);
        let mut f = Finding::new("r", "m");
        f.suppressions.push(s.clone());
        assert!(!f.is_suppressed());
        s.status = None;
        f.suppressions.push(s);
        assert!(f.is_suppressed());
    }
}
