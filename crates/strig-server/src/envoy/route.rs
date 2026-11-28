//! The route table: method and path pattern to a rule, and the resource template.
//!
//! Nothing here decides access. A path that cannot be matched with certainty (dot segments, an
//! encoded separator, bad UTF-8) matches no route, and a request that matches no route is denied.

use std::collections::{BTreeMap, BTreeSet};

use super::EnvoyConfigError;

/// Most segments of a path the adapter looks at. A longer one matches no route.
const MAX_SEGMENTS: usize = 64;

/// What a route requires.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteRule {
    /// Open to everyone, with or without a subject.
    Public,
    /// The subject must hold `permission` on the resource the template builds.
    Require {
        permission: String,
        resource: ResourceTemplate,
    },
}

impl RouteRule {
    /// A route that needs no decision.
    pub fn public() -> Self {
        Self::Public
    }

    /// A route that asks the engine for `permission` on `resource`.
    pub fn require(permission: impl Into<String>, resource: ResourceTemplate) -> Self {
        Self::Require {
            permission: permission.into(),
            resource,
        }
    }
}

/// The resource of a route, built from the path parameters: `kind` and `id` are literals with
/// optional `{param}` placeholders, as in `ResourceTemplate::new("document", "{id}")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTemplate {
    kind: Template,
    id: Template,
}

impl ResourceTemplate {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: Template::parse(&kind.into()),
            id: Template::parse(&id.into()),
        }
    }

    pub(crate) fn render(&self, params: &BTreeMap<String, String>) -> Option<(String, String)> {
        let kind = self.kind.render(params)?;
        let id = self.id.render(params)?;
        (!kind.is_empty() && !id.is_empty()).then_some((kind, id))
    }

    fn check(&self, known: &BTreeSet<&str>) -> Result<(), EnvoyConfigError> {
        for part in [&self.kind, &self.id] {
            let unknown = part.names().any(|name| !known.contains(name));
            if unknown || part.malformed {
                return Err(EnvoyConfigError::InvalidTemplate);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Template {
    parts: Vec<Piece>,
    malformed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Param(String),
}

impl Template {
    fn parse(text: &str) -> Self {
        let mut parts = Vec::new();
        let mut malformed = false;
        let mut rest = text;
        while let Some(open) = rest.find(['{', '}']) {
            if rest.as_bytes()[open] == b'}' {
                malformed = true;
                break;
            }
            if open > 0 {
                parts.push(Piece::Text(rest[..open].to_string()));
            }
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                malformed = true;
                break;
            };
            let name = &after[..close];
            if !valid_name(name) {
                malformed = true;
                break;
            }
            parts.push(Piece::Param(name.to_string()));
            rest = &after[close + 1..];
        }
        if !malformed && !rest.is_empty() {
            parts.push(Piece::Text(rest.to_string()));
        }
        Self { parts, malformed }
    }

    fn names(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|piece| match piece {
            Piece::Param(name) => Some(name.as_str()),
            Piece::Text(_) => None,
        })
    }

    fn render(&self, params: &BTreeMap<String, String>) -> Option<String> {
        let mut out = String::new();
        for piece in &self.parts {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Param(name) => out.push_str(params.get(name)?),
            }
        }
        Some(out)
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Param(String),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    segments: Vec<Segment>,
    /// Ends in `**`: any number of further segments.
    open_end: bool,
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, EnvoyConfigError> {
        let body = text.strip_prefix('/').ok_or(EnvoyConfigError::InvalidPattern)?;
        let mut segments = Vec::new();
        let mut open_end = false;
        let mut names = BTreeSet::new();
        let raw: Vec<&str> = if body.is_empty() {
            Vec::new()
        } else {
            body.split('/').collect()
        };
        for (index, part) in raw.iter().enumerate() {
            if open_end {
                return Err(EnvoyConfigError::InvalidPattern);
            }
            match *part {
                "" | "." | ".." => return Err(EnvoyConfigError::InvalidPattern),
                "**" => {
                    if index + 1 != raw.len() {
                        return Err(EnvoyConfigError::InvalidPattern);
                    }
                    open_end = true;
                }
                "*" => segments.push(Segment::Any),
                other if other.starts_with('{') && other.ends_with('}') => {
                    let name = &other[1..other.len() - 1];
                    if !valid_name(name) || !names.insert(name) {
                        return Err(EnvoyConfigError::InvalidPattern);
                    }
                    segments.push(Segment::Param(name.to_string()));
                }
                other if other.contains(['{', '}', '*', '%', '\\']) => return Err(EnvoyConfigError::InvalidPattern),
                other => segments.push(Segment::Literal(other.to_string())),
            }
        }
        Ok(Self { segments, open_end })
    }

    fn param_names(&self) -> BTreeSet<&str> {
        self.segments
            .iter()
            .filter_map(|segment| match segment {
                Segment::Param(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn matches(&self, path: &[String]) -> Option<BTreeMap<String, String>> {
        if path.len() < self.segments.len() || (!self.open_end && path.len() != self.segments.len()) {
            return None;
        }
        let mut params = BTreeMap::new();
        for (segment, actual) in self.segments.iter().zip(path) {
            match segment {
                Segment::Literal(expected) if expected == actual => {}
                Segment::Literal(_) => return None,
                Segment::Any => {}
                Segment::Param(name) => {
                    params.insert(name.clone(), actual.clone());
                }
            }
        }
        Some(params)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Methods {
    Any,
    Only(BTreeSet<String>),
}

impl Methods {
    fn parse(text: &str) -> Result<Self, EnvoyConfigError> {
        if text.trim() == "*" {
            return Ok(Self::Any);
        }
        let set: BTreeSet<String> = text
            .split(',')
            .map(|method| method.trim().to_ascii_uppercase())
            .collect();
        let valid = |m: &String| !m.is_empty() && m.bytes().all(|b| b.is_ascii_alphabetic());
        if set.is_empty() || !set.iter().all(valid) {
            return Err(EnvoyConfigError::InvalidMethod);
        }
        Ok(Self::Only(set))
    }

    fn allows(&self, method: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(set) => set.contains(&method.to_ascii_uppercase()),
        }
    }
}

#[derive(Debug, Clone)]
struct Route {
    methods: Methods,
    pattern: Pattern,
    rule: RouteRule,
}

/// What a request matched: the rule and the parameters of the path.
pub(crate) struct Matched<'a> {
    pub rule: &'a RouteRule,
    pub params: BTreeMap<String, String>,
}

/// The routes in the order they were added; the first that matches decides.
#[derive(Debug, Clone, Default)]
pub(crate) struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    pub fn push(&mut self, methods: &str, pattern: &str, rule: RouteRule) -> Result<(), EnvoyConfigError> {
        let methods = Methods::parse(methods)?;
        let pattern = Pattern::parse(pattern)?;
        if let RouteRule::Require { resource, permission } = &rule {
            if permission.is_empty() {
                return Err(EnvoyConfigError::InvalidRule);
            }
            resource.check(&pattern.param_names())?;
        }
        self.routes.push(Route { methods, pattern, rule });
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The first route for `method` and `path` (Envoy's `:path`, query included), or `None`.
    pub fn find(&self, method: &str, path: &str) -> Option<Matched<'_>> {
        let segments = segments_of(path)?;
        self.routes.iter().find_map(|route| {
            if !route.methods.allows(method) {
                return None;
            }
            route.pattern.matches(&segments).map(|params| Matched {
                rule: &route.rule,
                params,
            })
        })
    }
}

/// The decoded segments of a request path, or `None` when it cannot be trusted: no leading `/`,
/// an empty segment in the middle, a dot segment, an encoded `/`, `\` or NUL, invalid UTF-8, or
/// too many segments. The query and the fragment are dropped.
fn segments_of(raw: &str) -> Option<Vec<String>> {
    let path = raw.split(['?', '#']).next()?;
    let body = path.strip_prefix('/')?;
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for part in body.split('/') {
        if out.len() == MAX_SEGMENTS {
            return None;
        }
        let decoded = percent_decode(part)?;
        let bad = decoded.is_empty() || decoded == "." || decoded == ".." || decoded.contains(['/', '\\', '\0']);
        if bad {
            return None;
        }
        out.push(decoded);
    }
    Some(out)
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let value = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            out.push(value);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RouteTable {
        let mut table = RouteTable::default();
        table.push("GET", "/health", RouteRule::public()).expect("route");
        table
            .push(
                "GET,HEAD",
                "/documents/{id}",
                RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
            )
            .expect("route");
        table
            .push(
                "*",
                "/orgs/{org}/files/**",
                RouteRule::require("file.use", ResourceTemplate::new("file", "{org}-x")),
            )
            .expect("route");
        table
    }

    #[test]
    fn matches_method_and_pattern_and_keeps_the_parameters() {
        let table = table();
        let hit = table.find("get", "/documents/d1?x=1").expect("match");
        assert_eq!(hit.params.get("id").map(String::as_str), Some("d1"));
        assert!(table.find("POST", "/documents/d1").is_none());
        assert!(table.find("GET", "/documents").is_none());
        assert!(table.find("GET", "/documents/d1/extra").is_none());
        assert!(table.find("GET", "/documents/d1/").is_some());
        assert!(table.find("DELETE", "/orgs/o1/files/a/b/c").is_some());
        assert!(table.find("GET", "/orgs/o1/files").is_some());
    }

    #[test]
    fn a_path_that_cannot_be_trusted_matches_nothing() {
        let table = table();
        for path in [
            "/documents/../health",
            "/documents//d1",
            "/documents/%2e%2e",
            "/documents/a%2Fb",
            "/documents/a%5Cb",
            "/documents/%00",
            "/documents/%ff",
            "/documents/%zz",
            "documents/d1",
            "",
        ] {
            assert!(table.find("GET", path).is_none(), "{path}");
        }
    }

    #[test]
    fn parameters_are_decoded() {
        let table = table();
        let hit = table.find("GET", "/documents/a%20b").expect("match");
        assert_eq!(hit.params.get("id").map(String::as_str), Some("a b"));
    }

    #[test]
    fn a_route_that_cannot_work_is_refused_at_configuration() {
        let mut table = RouteTable::default();
        let rule = |id: &str| RouteRule::require("p", ResourceTemplate::new("document", id));
        assert!(table.push("GET", "/a/{id}", rule("{other}")).is_err());
        assert!(table.push("GET", "/a/{id}", rule("{id")).is_err());
        assert!(table.push("GET", "/a/{id}/{id}", rule("{id}")).is_err());
        assert!(table.push("GET", "/a/**/b", RouteRule::public()).is_err());
        assert!(table.push("GET", "a", RouteRule::public()).is_err());
        assert!(table.push("G ET", "/a", RouteRule::public()).is_err());
        assert!(
            table
                .push(
                    "GET",
                    "/a/{id}",
                    RouteRule::require("", ResourceTemplate::new("d", "{id}"))
                )
                .is_err()
        );
        assert!(table.is_empty());
    }
}
