# flux

A SARIF 2.1.0 profile for Kudzu: the tools (scurf, spall, taphttp, sarifview, sec-actions, ghas-actions) and the Kudzu platform that tracks what they find.

flux is not a new schema. A flux document is valid SARIF; flux adds conventions for fingerprints, triage, DAST evidence, and redaction. See [SPEC.md](SPEC.md).

## The crate

flux is also the Rust crate every Rust tool in Kudzu uses for findings, so none defines its own.

- `Finding` (a SARIF `result`) and `Report` (a SARIF log), read and written as SARIF with serde. The `flux/` properties are typed fields; SARIF fields the crate doesn't model are kept as they were.
- `fingerprint::dast_v1` / `sast_v1`: the frozen fingerprint algorithms.
- `validate::validate`: the profile's rules beyond SARIF's schema, including that a document marked redacted has nothing left to redact.
- `redact::redact_finding` / `redact_report` / `preview`: what every producer runs before a document leaves its store (SPEC.md, "Redaction"). Secrets become `[REDACTED:<kind>]` and the finding is marked `flux/redacted: true`.
- `examples/`: a golden file for each flow in the spec. Every one is checked against the official SARIF 2.1.0 schema, the flux rules, and an exact round trip.

```toml
[dependencies]
flux = { git = "https://github.com/cschooley/flux", tag = "v0.2.0" }
```

```rust
use flux::{fingerprint, Finding, Location, Report, Status, Taxon, ToolComponent};

let mut f = Finding::new("WSTG-INPV-05", "A quote in sort breaks the SQL query.");
f.fingerprints.insert(
    fingerprint::DAST_V1.into(),
    fingerprint::dast_v1("shop.example", "GET", "/api/products/17", Some("sort"), "WSTG-INPV-05"),
);
f.locations.push(Location::endpoint("GET", "https://shop.example/api/products/17?sort=x"));
f.taxa.push(Taxon::cwe(89));
f.properties.status = Some(Status::Candidate);
let report = Report::new(ToolComponent::tool("spall", "0.4.0"), vec![f]);
assert!(flux::validate::validate(&report).is_empty());
```

Not yet: a validator CLI.

## Development

`cargo test` and `cargo clippy --all-targets -- -D warnings`, on Rust 1.90.

## Provenance

Built with Claude Code, human-directed and reviewed.
