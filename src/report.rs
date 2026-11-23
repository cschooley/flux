//! `Report`: a flux document, which is a SARIF 2.1.0 log.

use serde::{Deserialize, Serialize};

use crate::finding::{Extra, Finding, Message, Taxon, CWE};

pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub runs: Vec<Run>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Report {
    /// One run of `driver` with `results`. Declares the CWE taxonomy when
    /// a result or rule refers to it.
    pub fn new(driver: ToolComponent, results: Vec<Finding>) -> Self {
        let mut run = Run {
            tool: Tool {
                driver,
                extra: Extra::new(),
            },
            results,
            taxonomies: vec![],
            extra: Extra::new(),
        };
        if run.uses_taxonomy(CWE) {
            run.taxonomies.push(ToolComponent::cwe());
        }
        Report {
            schema: Some(SARIF_SCHEMA.into()),
            version: SARIF_VERSION.into(),
            runs: vec![run],
            extra: Extra::new(),
        }
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.runs.iter().flat_map(|r| r.results.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    /// Always written: in SARIF an empty array means "nothing found",
    /// while an absent one means "not known".
    #[serde(default)]
    pub results: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomies: Vec<ToolComponent>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Run {
    /// Whether any result or rule refers to the taxonomy `name`.
    pub fn uses_taxonomy(&self, name: &str) -> bool {
        let in_results = self
            .results
            .iter()
            .flat_map(|f| &f.taxa)
            .any(|t| t.taxonomy() == Some(name));
        let in_rules = self
            .tool
            .driver
            .rules
            .iter()
            .flat_map(|r| &r.relationships)
            .any(|rel| rel.target.taxonomy() == Some(name));
        in_results || in_rules
    }

    pub fn declares_taxonomy(&self, name: &str) -> bool {
        self.taxonomies.iter().any(|t| t.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub driver: ToolComponent,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A SARIF `toolComponent`: a tool's driver, or a taxonomy such as CWE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolComponent {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl ToolComponent {
    pub fn tool(name: &str, version: &str) -> Self {
        ToolComponent {
            name: name.into(),
            version: Some(version.into()),
            ..Default::default()
        }
    }

    /// The CWE taxonomy that `Taxon::cwe` references point to.
    pub fn cwe() -> Self {
        ToolComponent {
            name: CWE.into(),
            information_uri: Some("https://cwe.mitre.org/".into()),
            ..Default::default()
        }
    }
}

/// A rule (SARIF `reportingDescriptor`): one vuln class a tool reports.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_description: Option<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// e.g. the CWE this rule tests for (`Rule::with_cwe`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Rule {
    pub fn new(id: &str, short: &str) -> Self {
        Rule {
            id: id.into(),
            short_description: Some(Message::new(short)),
            ..Default::default()
        }
    }

    pub fn with_cwe(mut self, id: u32) -> Self {
        self.relationships.push(Relationship {
            target: Taxon::cwe(id),
            kinds: vec!["relevant".into()],
            extra: Extra::new(),
        });
        self
    }

    pub fn cwes(&self) -> Vec<u32> {
        self.relationships
            .iter()
            .filter_map(|r| r.target.cwe_id())
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    pub target: Taxon,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_report_declares_cwe_only_when_used() {
        let plain = Report::new(
            ToolComponent::tool("spall", "0.4.0"),
            vec![Finding::new("r", "m")],
        );
        assert!(plain.runs[0].taxonomies.is_empty());

        let mut f = Finding::new("r", "m");
        f.taxa.push(Taxon::cwe(89));
        let r = Report::new(ToolComponent::tool("spall", "0.4.0"), vec![f]);
        assert!(r.runs[0].declares_taxonomy(CWE));

        let mut driver = ToolComponent::tool("spall", "0.4.0");
        driver
            .rules
            .push(Rule::new("WSTG-INPV-05", "SQL injection").with_cwe(89));
        assert!(Report::new(driver, vec![]).runs[0].declares_taxonomy(CWE));
    }

    #[test]
    fn report_shape() {
        let r = Report::new(ToolComponent::tool("spall", "0.4.0"), vec![]);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "spall", "version": "0.4.0"}}, "results": []}]})
        );
        assert_eq!(Report::from_json(&r.to_json_pretty().unwrap()).unwrap(), r);
    }

    #[test]
    fn rule_cwe_relationship() {
        let rule = Rule::new("WSTG-INPV-05", "SQL injection").with_cwe(89);
        assert_eq!(rule.cwes(), vec![89]);
        assert_eq!(
            serde_json::to_value(&rule.relationships[0]).unwrap(),
            json!({"target": {"id": "89", "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]})
        );
    }
}
