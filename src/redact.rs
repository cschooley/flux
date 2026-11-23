//! Redaction (SPEC.md, "Redaction"): what every producer runs before a flux
//! document leaves its local store. Secrets are replaced with
//! `[REDACTED:<kind>]` and the finding is marked `flux/redacted: true`.
//!
//! - Headers named in [`SECRET_HEADERS`] lose their whole value.
//! - Everywhere else (other header values, bodies, URLs, messages,
//!   location URIs): JWTs, bearer tokens, well-known API-key formats,
//!   passwords in URLs (`user:pass@`), and the values of sensitive names
//!   ([`SECRET_NAMES`]) in `name=value` pairs and JSON `"name": "value"`.
//! - Binary bodies can't be inspected, so they are dropped.
//!
//! Redaction is idempotent: a redacted document has nothing left to find,
//! which is what [`crate::validate`] checks for documents that claim it.
//! Fields the crate doesn't model (`extra`) are not inspected; producers
//! must not put secrets there.

use std::fmt;

use serde::Serialize;

use crate::finding::{ArtifactContent, Finding, Location};
use crate::report::Report;

/// What was found. Written into the placeholder: `[REDACTED:cookie]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Authorization,
    ProxyAuthorization,
    Cookie,
    SetCookie,
    ApiKey,
    Jwt,
    Bearer,
    Password,
    Token,
    Binary,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Authorization => "authorization",
            Kind::ProxyAuthorization => "proxy-authorization",
            Kind::Cookie => "cookie",
            Kind::SetCookie => "set-cookie",
            Kind::ApiKey => "api-key",
            Kind::Jwt => "jwt",
            Kind::Bearer => "bearer",
            Kind::Password => "password",
            Kind::Token => "token",
            Kind::Binary => "binary",
        }
    }

    fn placeholder(self) -> String {
        format!("[REDACTED:{}]", self.as_str())
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Headers whose whole value is a secret (lowercase).
pub const SECRET_HEADERS: &[(&str, Kind)] = &[
    ("authorization", Kind::Authorization),
    ("proxy-authorization", Kind::ProxyAuthorization),
    ("cookie", Kind::Cookie),
    ("set-cookie", Kind::SetCookie),
    ("x-api-key", Kind::ApiKey),
    ("api-key", Kind::ApiKey),
    ("x-auth-token", Kind::Token),
    ("x-access-token", Kind::Token),
];

/// Parameter and field names whose value is a secret, compared lowercase
/// with `-` and `_` removed.
pub const SECRET_NAMES: &[(&str, Kind)] = &[
    ("password", Kind::Password),
    ("passwd", Kind::Password),
    ("pwd", Kind::Password),
    ("pass", Kind::Password),
    ("passphrase", Kind::Password),
    ("secret", Kind::Token),
    ("clientsecret", Kind::Token),
    ("token", Kind::Token),
    ("accesstoken", Kind::Token),
    ("refreshtoken", Kind::Token),
    ("idtoken", Kind::Token),
    ("authtoken", Kind::Token),
    ("sessionid", Kind::Token),
    ("session", Kind::Token),
    ("sid", Kind::Token),
    ("privatekey", Kind::Token),
    ("apikey", Kind::ApiKey),
    ("apisecret", Kind::ApiKey),
];

/// The kind for a secret header, if `name` is one.
pub fn secret_header(name: &str) -> Option<Kind> {
    let n = name.trim().to_ascii_lowercase();
    SECRET_HEADERS
        .iter()
        .find(|(h, _)| *h == n)
        .map(|(_, k)| *k)
}

/// The kind for a sensitive parameter or field name, if `name` is one.
pub fn secret_name(name: &str) -> Option<Kind> {
    let n: String = name
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_NAMES.iter().find(|(s, _)| *s == n).map(|(_, k)| *k)
}

/// One thing redaction changed (or, in a dry run, would change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// Where: `webRequest.headers["cookie"]`, `webResponse.body`, ...
    pub at: String,
    pub kind: Kind,
}

const REDACTED: &str = "[REDACTED:";

/// Redact `text`: every pattern above except header names. Returns the
/// new text and what was found, in order.
pub fn redact_text(text: &str) -> (String, Vec<Kind>) {
    let mut found = Vec::new();
    let mut s = jwts(text, &mut found);
    s = bearers(&s, &mut found);
    s = api_keys(&s, &mut found);
    s = url_passwords(&s, &mut found);
    s = json_pairs(&s, &mut found);
    s = name_value_pairs(&s, &mut found);
    (s, found)
}

/// Redact a header value: the whole value for a secret header, else the
/// text patterns.
pub fn redact_header(name: &str, value: &str) -> (String, Vec<Kind>) {
    match secret_header(name) {
        Some(_) if value.starts_with(REDACTED) => (value.to_string(), vec![]),
        Some(k) => (k.placeholder(), vec![k]),
        None => redact_text(value),
    }
}

/// Redact a finding in place and mark it `flux/redacted: true`. Returns
/// what changed.
pub fn redact_finding(f: &mut Finding) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut text = |at: &str, s: &mut String| {
        let (new, kinds) = redact_text(s);
        for k in kinds {
            changes.push(Change {
                at: at.to_string(),
                kind: k,
            });
        }
        *s = new;
    };
    text("message.text", &mut f.message.text);
    for (i, l) in f.locations.iter_mut().enumerate() {
        location(&format!("locations[{i}]"), l, &mut text);
    }
    for (i, l) in f.related_locations.iter_mut().enumerate() {
        location(&format!("relatedLocations[{i}]"), l, &mut text);
    }
    let mut more = Vec::new();
    if let Some(req) = &mut f.web_request {
        if let Some(t) = &mut req.target {
            text("webRequest.target", t);
        }
        headers("webRequest", &mut req.headers, &mut more);
        body("webRequest.body", &mut req.body, &mut more);
    }
    if let Some(res) = &mut f.web_response {
        headers("webResponse", &mut res.headers, &mut more);
        body("webResponse.body", &mut res.body, &mut more);
    }
    changes.extend(more);
    f.properties.redacted = Some(true);
    changes
}

/// What [`redact_finding`] would change, without changing `f`.
pub fn preview(f: &Finding) -> (Finding, Vec<Change>) {
    let mut copy = f.clone();
    let changes = redact_finding(&mut copy);
    (copy, changes)
}

/// Redact every finding in a report. Returns the changes per result, as
/// `runs[r].results[i].<at>`.
pub fn redact_report(r: &mut Report) -> Vec<Change> {
    let mut all = Vec::new();
    for (ri, run) in r.runs.iter_mut().enumerate() {
        for (fi, f) in run.results.iter_mut().enumerate() {
            for c in redact_finding(f) {
                all.push(Change {
                    at: format!("runs[{ri}].results[{fi}].{}", c.at),
                    kind: c.kind,
                });
            }
        }
    }
    all
}

/// Mark a finding as deliberately unredacted (the explicit opt-in), so
/// consumers can refuse it.
pub fn mark_unredacted(f: &mut Finding) {
    f.properties.redacted = Some(false);
}

fn location(at: &str, l: &mut Location, text: &mut impl FnMut(&str, &mut String)) {
    if let Some(p) = &mut l.physical_location {
        text(
            &format!("{at}.physicalLocation.artifactLocation.uri"),
            &mut p.artifact_location.uri,
        );
    }
    if let Some(m) = &mut l.message {
        text(&format!("{at}.message.text"), &mut m.text);
    }
}

fn headers(
    at: &str,
    h: &mut std::collections::BTreeMap<String, String>,
    changes: &mut Vec<Change>,
) {
    for (name, value) in h.iter_mut() {
        let (new, kinds) = redact_header(name, value);
        for k in kinds {
            changes.push(Change {
                at: format!("{at}.headers[\"{name}\"]"),
                kind: k,
            });
        }
        *value = new;
    }
}

fn body(at: &str, b: &mut Option<ArtifactContent>, changes: &mut Vec<Change>) {
    let Some(c) = b else { return };
    if c.binary.is_some() {
        c.binary = None;
        c.text = Some(Kind::Binary.placeholder());
        changes.push(Change {
            at: at.into(),
            kind: Kind::Binary,
        });
        return;
    }
    if let Some(t) = &mut c.text {
        let (new, kinds) = redact_text(t);
        for k in kinds {
            changes.push(Change {
                at: at.into(),
                kind: k,
            });
        }
        *t = new;
    }
}

// --- patterns (no regex crate: the core stays small) ---

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-._~+/=".contains(&c)
}

/// Not preceded by a character that would make `at` the middle of a word.
fn boundary(b: &[u8], at: usize) -> bool {
    at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_' || b[at - 1] == b'-')
}

/// Rebuild `s`, replacing each `(start, end, kind, keep)` span: `keep`
/// bytes at its start stay (e.g. "Bearer ").
fn splice(s: &str, spans: Vec<(usize, usize, Kind, usize)>, found: &mut Vec<Kind>) -> String {
    if spans.is_empty() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (start, end, kind, keep) in spans {
        out.push_str(&s[last..start + keep]);
        out.push_str(&kind.placeholder());
        found.push(kind);
        last = end;
    }
    out.push_str(&s[last..]);
    out
}

/// `eyJ<b64url>.<b64url>.<b64url>*`
fn jwts(s: &str, found: &mut Vec<Kind>) -> String {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(off) = s[i..].find("eyJ") {
        let start = i + off;
        let mut j = start;
        let mut parts = [0usize; 3];
        let mut p = 0;
        while j < b.len() && p < 3 {
            if is_b64url(b[j]) {
                parts[p] += 1;
                j += 1;
            } else if b[j] == b'.' && p < 2 {
                p += 1;
                j += 1;
            } else {
                break;
            }
        }
        if boundary(b, start) && p == 2 && parts[0] >= 4 && parts[1] >= 4 {
            spans.push((start, j, Kind::Jwt, 0));
            i = j;
        } else {
            i = start + 3;
        }
    }
    splice(s, spans, found)
}

/// `Bearer <token>` (any case), keeping the scheme.
fn bearers(s: &str, found: &mut Vec<Kind>) -> String {
    let lower = s.to_ascii_lowercase();
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(off) = lower[i..].find("bearer") {
        let start = i + off;
        let mut j = start + 6;
        let ws = j;
        while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
            j += 1;
        }
        let tok = j;
        while j < b.len() && is_token(b[j]) {
            j += 1;
        }
        if boundary(b, start) && tok > ws && j - tok >= 8 {
            spans.push((start, j, Kind::Bearer, tok - start));
            i = j;
        } else {
            i = start + 6;
        }
    }
    splice(s, spans, found)
}

/// Well-known API-key formats.
/// (prefix, minimum length after it, which bytes may follow).
type KeyFormat = (&'static str, usize, fn(u8) -> bool);

const KEY_PREFIXES: &[KeyFormat] = &[
    ("AKIA", 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit()),
    ("ASIA", 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit()),
    ("ghp_", 30, |c| c.is_ascii_alphanumeric()),
    ("gho_", 30, |c| c.is_ascii_alphanumeric()),
    ("ghu_", 30, |c| c.is_ascii_alphanumeric()),
    ("ghs_", 30, |c| c.is_ascii_alphanumeric()),
    ("ghr_", 30, |c| c.is_ascii_alphanumeric()),
    ("github_pat_", 20, |c| {
        c.is_ascii_alphanumeric() || c == b'_'
    }),
    ("glpat-", 20, |c| {
        c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
    }),
    ("sk_live_", 16, |c| c.is_ascii_alphanumeric()),
    ("sk_test_", 16, |c| c.is_ascii_alphanumeric()),
    ("rk_live_", 16, |c| c.is_ascii_alphanumeric()),
    ("xoxb-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxp-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxa-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxr-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("xoxs-", 10, |c| c.is_ascii_alphanumeric() || c == b'-'),
    ("AIza", 35, |c| {
        c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
    }),
];

fn api_keys(s: &str, found: &mut Vec<Kind>) -> String {
    let b = s.as_bytes();
    let mut spans: Vec<(usize, usize, Kind, usize)> = Vec::new();
    for (prefix, min, ok) in KEY_PREFIXES {
        let mut i = 0;
        while let Some(off) = s[i..].find(prefix) {
            let start = i + off;
            let mut j = start + prefix.len();
            while j < b.len() && ok(b[j]) {
                j += 1;
            }
            let overlaps = spans.iter().any(|(a, e, _, _)| start < *e && *a < j);
            if boundary(b, start) && j - start - prefix.len() >= *min && !overlaps {
                spans.push((start, j, Kind::ApiKey, 0));
                i = j;
            } else {
                i = start + prefix.len();
            }
        }
    }
    spans.sort_by_key(|s| s.0);
    splice(s, spans, found)
}

/// `scheme://user:password@host`: the password.
fn url_passwords(s: &str, found: &mut Vec<Kind>) -> String {
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(off) = s[i..].find("://") {
        let auth = i + off + 3;
        let end = s[auth..]
            .find(['/', '?', '#', ' ', '\n', '"', '\''])
            .map_or(s.len(), |e| auth + e);
        if let Some(at) = s[auth..end].rfind('@') {
            let userinfo = &s[auth..auth + at];
            if let Some(colon) = userinfo.find(':') {
                let p = auth + colon + 1;
                let e = auth + at;
                if e > p && !s[p..e].starts_with(REDACTED) {
                    spans.push((p, e, Kind::Password, 0));
                }
            }
        }
        i = auth;
    }
    splice(s, spans, found)
}

/// `"name": "value"` (JSON, even when the text isn't valid JSON).
fn json_pairs(s: &str, found: &mut Vec<Kind>) -> String {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(off) = s[i..].find('"') {
        let q1 = i + off;
        let Some(len) = s[q1 + 1..].find('"') else {
            break;
        };
        let q2 = q1 + 1 + len;
        let name = &s[q1 + 1..q2];
        i = q2 + 1;
        let Some(kind) = secret_name(name) else {
            continue;
        };
        let mut j = q2 + 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= b.len() || b[j] != b':' {
            continue;
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'"' {
            // A string value, up to the next unescaped quote.
            let vs = j + 1;
            let mut k = vs;
            while k < b.len() && b[k] != b'"' {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            let ve = k.min(b.len());
            if ve > vs && !s[vs..ve].starts_with(REDACTED) {
                spans.push((vs, ve, kind, 0));
            }
            i = (ve + 1).min(b.len()).max(i);
        } else {
            // A bare value (number, true): up to , } ] or whitespace.
            let vs = j;
            let mut k = vs;
            while k < b.len() && !b",}] \n\r\t".contains(&b[k]) {
                k += 1;
            }
            if k > vs && &s[vs..k] != "null" {
                spans.push((vs, k, kind, 0));
            }
            i = k.max(i);
        }
    }
    splice(s, spans, found)
}

/// `name=value` in query strings, form bodies, cookies-like text.
fn name_value_pairs(s: &str, found: &mut Vec<Kind>) -> String {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(off) = s[i..].find('=') {
        let eq = i + off;
        // The name: back to a separator.
        let mut ns = eq;
        while ns > 0 && !b"?&; \n\r\t\"',{(".contains(&b[ns - 1]) {
            ns -= 1;
        }
        let name = &s[ns..eq];
        let mut ve = eq + 1;
        while ve < b.len() && !b"&; \n\r\t\"'#,})".contains(&b[ve]) {
            ve += 1;
        }
        if let Some(kind) = secret_name(name) {
            if ve > eq + 1 && !s[eq + 1..ve].starts_with(REDACTED) {
                spans.push((eq + 1, ve, kind, 0));
            }
        }
        i = ve.max(eq + 1);
    }
    splice(s, spans, found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Location, WebRequest, WebResponse};

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLWJ5dGVz";

    fn red(s: &str) -> String {
        redact_text(s).0
    }

    #[test]
    fn jwts_and_bearers() {
        assert_eq!(red(&format!("token {JWT} end")), "token [REDACTED:jwt] end");
        assert_eq!(
            red(&format!("Authorization: Bearer {JWT}")),
            "Authorization: Bearer [REDACTED:jwt]"
        );
        assert_eq!(red("bearer abc123def456ghi"), "bearer [REDACTED:bearer]");
        assert_eq!(red("BEARER  x.y-z~abc/123=="), "BEARER  [REDACTED:bearer]");
        // Too short, or the word in prose, or not a JWT.
        assert_eq!(red("bearer short"), "bearer short");
        assert_eq!(red("the bearer of bad news"), "the bearer of bad news");
        assert_eq!(
            red("eyJ.x.y and keyJabc.defg.hij"),
            "eyJ.x.y and keyJabc.defg.hij"
        );
    }

    #[test]
    fn api_key_formats() {
        for (key, kind) in [
            ("AKIAIOSFODNN7EXAMPLE", Kind::ApiKey),
            ("ghp_0123456789abcdefghijABCDEFGHIJ0123", Kind::ApiKey),
            (
                "github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
                Kind::ApiKey,
            ),
            ("glpat-abcdefghij0123456789", Kind::ApiKey),
            ("sk_live_0123456789abcdefABCD", Kind::ApiKey),
            ("xoxb-123456789012-abcdefghij", Kind::ApiKey),
            ("AIzaSyA-0123456789abcdefghijklmnopqrstu", Kind::ApiKey),
        ] {
            let (out, found) = redact_text(&format!("key={key}x and \"{key}\""));
            assert!(!out.contains(key), "{key}: {out}");
            assert!(found.contains(&kind), "{key}");
        }
        assert_eq!(
            red("AKIA is a prefix; sk_live_short too"),
            "AKIA is a prefix; sk_live_short too"
        );
        assert_eq!(
            red("XAKIAIOSFODNN7EXAMPLE"),
            "XAKIAIOSFODNN7EXAMPLE",
            "mid-word isn't a key"
        );
    }

    #[test]
    fn secret_names_in_pairs_and_json() {
        assert_eq!(
            red("https://a.test/login?user=bob&password=hunter2&next=/x#f"),
            "https://a.test/login?user=bob&password=[REDACTED:password]&next=/x#f"
        );
        assert_eq!(
            red("access_token=abc.def&state=ok"),
            "access_token=[REDACTED:token]&state=ok"
        );
        assert_eq!(
            red("Api-Key=k1; theme=dark"),
            "Api-Key=[REDACTED:api-key]; theme=dark"
        );
        assert_eq!(
            red(
                r#"{"username": "bob", "password": "hun\"ter2", "pin": 1234, "token":null, "apiKey":12345}"#
            ),
            r#"{"username": "bob", "password": "[REDACTED:password]", "pin": 1234, "token":null, "apiKey":[REDACTED:api-key]}"#
        );
        // Names that merely contain a secret word are left alone.
        assert_eq!(
            red("passport=X123&tokens_left=3"),
            "passport=X123&tokens_left=3"
        );
        assert_eq!(secret_name("Client_Secret"), Some(Kind::Token));
        assert_eq!(secret_name("sessionId"), Some(Kind::Token));
        assert_eq!(secret_name("username"), None);
    }

    #[test]
    fn passwords_in_urls() {
        assert_eq!(
            red("https://bob:s3cret@a.test/x"),
            "https://bob:[REDACTED:password]@a.test/x"
        );
        assert_eq!(
            red("https://bob@a.test/x and ftp://a.test"),
            "https://bob@a.test/x and ftp://a.test"
        );
    }

    #[test]
    fn headers_by_name() {
        assert_eq!(
            redact_header("Cookie", "sid=1; theme=dark").0,
            "[REDACTED:cookie]"
        );
        assert_eq!(
            redact_header("AUTHORIZATION", "Basic Ym9iOnB3").0,
            "[REDACTED:authorization]"
        );
        assert_eq!(redact_header("x-api-key", "k").0, "[REDACTED:api-key]");
        assert_eq!(
            redact_header("content-type", "application/json").0,
            "application/json"
        );
        assert_eq!(
            redact_header("x-forwarded-for", &format!("1.2.3.4 {JWT}")).0,
            "1.2.3.4 [REDACTED:jwt]"
        );
        assert_eq!(redact_header("cookie", "[REDACTED:cookie]").1, vec![]);
    }

    fn evidence_finding() -> Finding {
        let mut f = Finding::new("WSTG-INPV-05", format!("SQLi with session {JWT}"));
        f.locations
            .push(Location::endpoint("GET", "https://a.test/p?x=1"));
        let mut req = WebRequest {
            target: Some("https://bob:pw@a.test/p?sort=x'&token=t0k3n".into()),
            method: Some("POST".into()),
            body: Some(ArtifactContent::text(r#"{"q":"x'","password":"hunter2"}"#)),
            ..Default::default()
        };
        req.headers
            .insert("cookie".into(), "sid=8f3a91c2; csrf=1".into());
        req.headers
            .insert("authorization".into(), format!("Bearer {JWT}"));
        req.headers.insert("accept".into(), "*/*".into());
        let mut res = WebResponse {
            status_code: Some(500),
            body: Some(ArtifactContent {
                binary: Some("AAEC".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        res.headers
            .insert("set-cookie".into(), "sid=new; HttpOnly".into());
        f.web_request = Some(req);
        f.web_response = Some(res);
        f
    }

    #[test]
    fn a_finding_is_redacted_everywhere_and_marked() {
        let mut f = evidence_finding();
        let changes = redact_finding(&mut f);
        let req = f.web_request.as_ref().unwrap();
        assert_eq!(req.headers["cookie"], "[REDACTED:cookie]");
        assert_eq!(req.headers["authorization"], "[REDACTED:authorization]");
        assert_eq!(req.headers["accept"], "*/*");
        assert_eq!(
            req.target.as_deref(),
            Some("https://bob:[REDACTED:password]@a.test/p?sort=x'&token=[REDACTED:token]")
        );
        assert_eq!(
            req.body.as_ref().unwrap().text.as_deref(),
            Some(r#"{"q":"x'","password":"[REDACTED:password]"}"#)
        );
        let res = f.web_response.as_ref().unwrap();
        assert_eq!(res.headers["set-cookie"], "[REDACTED:set-cookie]");
        assert_eq!(
            res.body.as_ref().unwrap(),
            &ArtifactContent::text("[REDACTED:binary]")
        );
        assert_eq!(f.message.text, "SQLi with session [REDACTED:jwt]");
        assert_eq!(f.properties.redacted, Some(true));
        let at: Vec<String> = changes
            .iter()
            .map(|c| format!("{} {}", c.at, c.kind))
            .collect();
        assert_eq!(
            at,
            [
                "message.text jwt",
                "webRequest.target password",
                "webRequest.target token",
                "webRequest.headers[\"authorization\"] authorization",
                "webRequest.headers[\"cookie\"] cookie",
                "webRequest.body password",
                "webResponse.headers[\"set-cookie\"] set-cookie",
                "webResponse.body binary",
            ]
        );
        // Idempotent: nothing left to find.
        let again = f.clone();
        assert!(redact_finding(&mut f).is_empty());
        assert_eq!(f, again);
    }

    #[test]
    fn preview_changes_nothing_and_unredacted_is_marked() {
        let f = evidence_finding();
        let (redacted, changes) = preview(&f);
        assert_eq!(f, evidence_finding());
        assert_eq!(changes.len(), 8);
        assert_eq!(redacted.properties.redacted, Some(true));
        let mut u = evidence_finding();
        mark_unredacted(&mut u);
        assert_eq!(u.properties.redacted, Some(false));
    }

    #[test]
    fn reports_are_redacted_per_result() {
        let mut r = Report::new(
            crate::ToolComponent::tool("spall", "0.5.0"),
            vec![evidence_finding(), Finding::new("r", "clean")],
        );
        let changes = redact_report(&mut r);
        assert_eq!(changes.len(), 8);
        assert!(changes[0].at.starts_with("runs[0].results[0]."));
        assert!(r.findings().all(|f| f.properties.redacted == Some(true)));
    }

    #[test]
    fn utf8_text_survives() {
        assert_eq!(
            red("пароль password=секрет ✓"),
            "пароль password=[REDACTED:password] ✓"
        );
        assert_eq!(red("Bearer ünïcode-not-token"), "Bearer ünïcode-not-token");
    }
}
