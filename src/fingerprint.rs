//! Fingerprints (SPEC.md, "Fingerprints"). Every producer computes them
//! here so they match across tools. The algorithms are frozen: a change is
//! a new version key (`flux/dast/v2`), never an edit to v1.

use sha2::{Digest, Sha256};

pub const DAST_V1: &str = "flux/dast/v1";
pub const SAST_V1: &str = "flux/sast/v1";

/// `flux/dast/v1`: SHA-256 (lowercase hex) of
/// `host | METHOD | normalized path | parameter | ruleId`.
///
/// - host: lowercased; give it as in the URL (no userinfo, no default port).
/// - method: uppercased.
/// - path: see [`normalize_path`].
/// - parameter: the parameter name, or empty when there is none.
pub fn dast_v1(
    host: &str,
    method: &str,
    path: &str,
    parameter: Option<&str>,
    rule_id: &str,
) -> String {
    hash(&[
        &host.to_ascii_lowercase(),
        &method.to_ascii_uppercase(),
        &normalize_path(path),
        parameter.unwrap_or(""),
        rule_id,
    ])
}

/// `flux/sast/v1`: SHA-256 (lowercase hex) of
/// `repo | file path | function/symbol | ruleId`. No line numbers: they drift.
pub fn sast_v1(repo: &str, file: &str, symbol: &str, rule_id: &str) -> String {
    hash(&[repo, file, symbol, rule_id])
}

/// The `flux/dast/v1` path: query and fragment removed; numeric and UUID
/// segments replaced with `{id}`; trailing slashes removed; always starts
/// with `/` (so the root is `/`). Case and percent-encoding are kept.
pub fn normalize_path(path: &str) -> String {
    let segs: Vec<&str> = strip_query(path)
        .trim_end_matches('/')
        .split('/')
        .map(|s| if is_id(s) { "{id}" } else { s })
        .collect();
    let joined = segs.join("/");
    if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    }
}

/// `url` up to its first `?` or `#`.
pub fn strip_query(url: &str) -> &str {
    url.find(['?', '#']).map_or(url, |i| &url[..i])
}

fn is_id(seg: &str) -> bool {
    (!seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())) || is_uuid(seg)
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn hash(parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("|").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_normalize() {
        assert_eq!(normalize_path("/api/users/42"), "/api/users/{id}");
        assert_eq!(normalize_path("/api/users/42/"), "/api/users/{id}");
        assert_eq!(normalize_path("/api/users/42?x=1#f"), "/api/users/{id}");
        assert_eq!(
            normalize_path("/o/6F1C2E3A-0000-4000-8000-000000000001/items"),
            "/o/{id}/items"
        );
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/?q=1"), "/");
        assert_eq!(normalize_path("a/b"), "/a/b");
        // Not ids: mixed, hex that isn't a UUID, versions. Case is kept.
        assert_eq!(
            normalize_path("/v2/item42/deadbeef/Users"),
            "/v2/item42/deadbeef/Users"
        );
        assert_eq!(
            normalize_path("/x/6f1c2e3a00004000800000000000000001"),
            "/x/6f1c2e3a00004000800000000000000001"
        );
    }

    // Pinned: computed independently (Python hashlib) from the joined input
    // shown. If one of these changes, the algorithm changed: that is v2.
    #[test]
    fn dast_v1_is_pinned() {
        assert_eq!(
            dast_v1(
                "A.test",
                "get",
                "/api/users/42?id=1",
                Some("id"),
                "WSTG-INPV-05"
            ),
            "957359703748d77650490c0ae8c832e708ea20565ca078e5a7e1ff5717590cf0" // a.test|GET|/api/users/{id}|id|WSTG-INPV-05
        );
        assert_eq!(
            dast_v1("a.test", "POST", "/", Some("q"), "WSTG-INPV-01"),
            "ee7471b3bcb62232fe9bee6caa5caf5f6ec61669431179b2495a8318525fef1a" // a.test|POST|/|q|WSTG-INPV-01
        );
        assert_eq!(
            dast_v1(
                "a.test",
                "GET",
                "/api/orders/6f1c2e3a-0000-4000-8000-000000000001/items/",
                None,
                "WSTG-ATHZ-04"
            ),
            "0387652df560fee844f4e0e1a0b33d1f55a1dd3e62b2a8748fa8fe521585e7c0" // a.test|GET|/api/orders/{id}/items||WSTG-ATHZ-04
        );
    }

    #[test]
    fn sast_v1_is_pinned() {
        assert_eq!(
            sast_v1("cschooley/shop", "src/db.rs", "find_user", "scurf/sqli"),
            "4ea166c22ee1bafcb956a158f1f7c0479005f2bb84ce2acc5939cb696a9b5c2f" // cschooley/shop|src/db.rs|find_user|scurf/sqli
        );
    }

    #[test]
    fn same_endpoint_same_fingerprint() {
        let a = dast_v1("a.test", "GET", "/u/1", Some("id"), "r");
        assert_eq!(a, dast_v1("A.TEST", "get", "/u/999/?z", Some("id"), "r"));
        assert_ne!(a, dast_v1("a.test", "GET", "/u/1", Some("name"), "r"));
        assert_ne!(a, dast_v1("a.test", "POST", "/u/1", Some("id"), "r"));
    }
}
