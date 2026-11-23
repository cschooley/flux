//! flux: a SARIF 2.1.0 profile for Kudzu (SPEC.md).
//!
//! The one set of finding types every Rust tool in Kudzu uses: a
//! [`Finding`] is a SARIF `result`, a [`Report`] is a SARIF log, and serde
//! reads and writes them as SARIF. Fingerprints ([`fingerprint`]) and the
//! profile's rules ([`validate`]) live here so producers agree on them.
//! Redaction comes next (SPEC.md, "Redaction").

#![forbid(unsafe_code)]

mod finding;
pub mod fingerprint;
mod report;
pub mod validate;

pub use finding::*;
pub use report::*;

// The README's example compiles and runs as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
