# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

flux is the shared findings layer for the cschooley security toolkit
(scurf, spall, taphttp, sarifview, sec-actions, ghas-actions, Kudzu).
It is two things:

1. **A spec** (`SPEC.md`): a profile of SARIF 2.1.0. Not a new schema.
2. **A Rust crate**: the one set of finding types, fingerprinting,
   redaction, and validation every Rust tool in the suite depends on.

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

TDD, same as the rest of the suite:

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

Spec draft v0.2. No crate code yet. First steps:

1. Cargo scaffold; evaluate an existing SARIF types crate
   (e.g. `serde-sarif`) vs. hand-written types for the profile subset.
2. `Finding` and friends, SARIF round-trip.
3. Fingerprints.
4. Redaction.
5. Validator (function + small CLI).
6. `examples/` golden files for each flow in `SPEC.md`.

## Provenance

Built with Claude Code, human-directed and reviewed. Stated openly,
not hidden.
