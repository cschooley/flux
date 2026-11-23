# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

flux is the shared findings layer for Kudzu
(scurf, spall, taphttp, sarifview, sec-actions, ghas-actions, Kudzu).
It is two things:

1. **A spec** (`SPEC.md`): a profile of SARIF 2.1.0. Not a new schema.
2. **A Rust crate**: the one set of finding types, fingerprinting,
   redaction, and validation every Rust tool in Kudzu depends on.

`SPEC.md` is the source of truth. If code and spec disagree, the spec
wins until someone deliberately changes the spec.

## Rules

- **Never invent fields SARIF already has.** Standard SARIF field
  first; a `flux/` property-bag key only for what SARIF lacks. Every
  new `flux/` key gets added to the table in `SPEC.md` in the same
  change.
- **Output must be valid SARIF 2.1.0.** Validate against the official
  schema in tests.
- **Fingerprint algorithms are versioned and frozen.** Changing one
  means a new version key (`flux/dast/v2`), never an edit to v1.
- **Redaction is not optional.** No export path may skip it without
  an explicit opt-in that sets `flux/redacted: false`.
- **Core stays small.** Format-specific adapters (OCSF, third-party
  SARIF, STIX / VEX / CycloneDX) are separate crates or feature flags,
  never core dependencies.
- **No tool-specific logic.** flux knows nothing about Kudzu, spall,
  or taphttp internals. Tools depend on flux, not the reverse.

## Testing

TDD, same as the rest of Kudzu:

- Test first. No behavior ships without a test that would catch its
  regression.
- Round-trip tests: `Finding` -> SARIF -> `Finding` is lossless.
- Golden files in `examples/` are the fixtures: every example must
  parse, validate, and round-trip.
- Fingerprint tests pin exact hash outputs for known inputs.
- Redaction tests cover headers, bodies, URLs, and JWT/bearer/API-key
  patterns.
- `cargo test` and `cargo clippy -- -D warnings` clean before
  committing.

## Status

Spec draft v0.4. Crate v0.1.0: `Finding` / `Report` (SARIF round-trip,
unknown fields kept), `flux/dast/v1` and `flux/sast/v1` fingerprints,
`validate` (the flux rules; SARIF schema validation runs in the tests
against `schema/sarif-schema-2.1.0.json`), and golden `examples/`.
Next:

1. Redaction (headers, bodies, URLs; JWT / bearer / API-key patterns),
   with tests for each.
2. Validator CLI (and a runtime SARIF schema check behind a feature).
3. `schema/flux-properties.schema.json`.

Dependencies: core is `serde`, `serde_json`, `sha2` only. New ones
(transitive included) at least two weeks old; pin with
`cargo update --precise`. `jsonschema` is a dev-dependency.

## Provenance

Built with Claude Code, human-directed and reviewed. Stated openly,
not hidden.
