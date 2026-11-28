//! Casbin: a `model.conf` and a `policy.csv`, read into a [`Policy`].
//!
//! The models covered are the common ones: ACL, RBAC (`g = _, _`, with domains `g = _, _, _`), RBAC
//! with a hierarchical resource through `keyMatch`, and ABAC over attributes of the request.
//!
//! - `p` lines become grants on the target kind `object` and the permissions `object.<action>`
//!   ([`CasbinImport::request`] maps a Casbin request to its Strig one).
//! - `g` lines become role assignments (`Policy::subjects`, scoped to the domain when there is
//!   one) and, between two roles, the [`RoleSpec`](crate::RoleSpec) inheritance.
//! - The effect becomes the strategy: `some(where (p.eft == allow))` the default one,
//!   `some(where (p.eft == allow)) && !some(where (p.eft == deny))` `deny_overrides`,
//!   `!some(where (p.eft == deny))` `deny_overrides` over a baseline `allow` of every action, and
//!   `priority(p.eft) || deny` `first_applicable` in the order of the lines (sorted by a `priority`
//!   field when the policy has one).
//! - A matcher is read as a disjunction of conjunctions; each conjunct is `r.sub == p.sub`,
//!   `g(r.sub, p.sub[, r.dom])`, `r.obj == p.obj`, `keyMatch(r.obj, p.obj)`, `r.act == p.act`,
//!   `regexMatch(r.act, p.act)` over alternations of literals, `r.dom == p.dom`, the same against a
//!   literal, or a comparison between attributes of the request and literals (a grant condition).
//!
//! What has no faithful translation is an [`ImportError`] with the position and the reason: a
//! function the conditions cannot express (`keyMatch2`..`keyMatch5`, `globMatch`, a real regular
//! expression), a negated policy field, `g2`, `p2`, `subjectPriority`.
//!
//! Casbin lets a request carry any action; here the actions are the ones the policy names (plus
//! [`Options::actions`]), and a request for another one has no permission, so it is denied.

use std::collections::{BTreeMap, BTreeSet};

use super::csv::{self, Record, column, line_number};
use super::{ImportError, Report, finish, is_name, key_segment, unique_id};
use crate::dsl::{Location, Policy};
use crate::{
    Anchor, CatalogExport, Condition, Grant, Operand, PermissionDef, Resource, RoleAssignment, RoleSpec, StrategySpec,
    Subject, SubjectMatcher, TargetSelector, Value,
};

const OBJECT: &str = "object";
const DOMAIN: &str = "domain";
const MAX_DISJUNCTS: usize = 64;

/// What the import is told besides the two texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Actions to add to the ones the policy names. A model that does not constrain the action
    /// (ABAC) has none of its own: name them here.
    pub actions: Vec<String>,
    /// Name of the model, in positions.
    pub model_file: String,
    /// Name of the policy, in positions.
    pub policy_file: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            actions: Vec::new(),
            model_file: "model.conf".to_string(),
            policy_file: "policy.csv".to_string(),
        }
    }
}

/// A Casbin model and policy, imported.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CasbinImport {
    policy: Policy,
    report: Report,
    permissions: BTreeMap<String, String>,
}

impl CasbinImport {
    /// The policy: catalog, role graph, role assignments and grants.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Takes the policy.
    pub fn into_policy(self) -> Policy {
        self.policy
    }

    /// What was converted and what was noted.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// The subject `sub`, with the roles the policy gives it.
    pub fn subject(&self, sub: &str) -> Subject {
        self.policy
            .subjects
            .iter()
            .find(|s| s.id.as_deref() == Some(sub))
            .cloned()
            .unwrap_or_else(|| Subject::user(sub))
    }

    /// The permission key and the resource of the Casbin request on `obj` with action `act` (and
    /// `dom`, in a model with domains). `None` when the action is not one the policy names: such a
    /// request has no permission and is denied.
    pub fn request(&self, obj: &str, act: &str, dom: Option<&str>) -> Option<(String, Resource)> {
        let permission = self.permissions.get(act)?.clone();
        let mut resource = Resource::new(OBJECT, obj);
        if let Some(dom) = dom {
            resource = resource.within(DOMAIN, dom);
        }
        Some((permission, resource))
    }
}

/// Reads a Casbin model and policy.
///
/// # Errors
/// [`ImportError`] with the position and the reason of everything that has no faithful translation.
pub fn import(model: &str, policy: &str, options: &Options) -> Result<CasbinImport, ImportError> {
    let mut report = Report::default();
    let model_file = options.model_file.as_str();
    let Some(def) = read_model(model, model_file, &mut report) else {
        return Err(ImportError { report });
    };
    let lines = read_policy(policy, options, &def, &mut report);
    if report.failed() {
        return Err(ImportError { report });
    }
    let disjuncts = analyze(&def, &mut report);
    if report.failed() {
        return Err(ImportError { report });
    }
    let built = build(&def, &lines, &disjuncts, options, &mut report);
    if report.failed() {
        return Err(ImportError { report });
    }
    let Some((policy, permissions)) = built else {
        return Err(ImportError { report });
    };
    let policy = policy.canonical();
    finish(&policy, &mut report);
    if report.failed() {
        return Err(ImportError { report });
    }
    Ok(CasbinImport {
        policy,
        report,
        permissions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dim {
    Sub,
    Obj,
    Act,
    Dom,
    Eft,
    Priority,
}

fn dim_of(name: &str) -> Option<Dim> {
    match name {
        "sub" | "subject" | "user" | "usr" => Some(Dim::Sub),
        "obj" | "object" | "res" | "resource" => Some(Dim::Obj),
        "act" | "action" => Some(Dim::Act),
        "dom" | "domain" | "tenant" => Some(Dim::Dom),
        "eft" => Some(Dim::Eft),
        "priority" => Some(Dim::Priority),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    AllowOnly,
    DenyBaseline,
    AllowAndDeny,
    Priority,
}

#[derive(Debug, Clone)]
struct Pos {
    line: u32,
    col: u32,
}

#[derive(Debug)]
struct ModelDef {
    request: Vec<(String, Dim)>,
    policy: Vec<(String, Dim)>,
    link_arity: Option<usize>,
    effect: Effect,
    matcher: String,
    matcher_at: Pos,
    file: String,
}

fn at(file: &str, pos: &Pos) -> Option<Location> {
    Some(Location::new(file, pos.line, pos.col, 1))
}

fn read_model(text: &str, file: &str, report: &mut Report) -> Option<ModelDef> {
    let mut section = String::new();
    let mut request = None;
    let mut policy_fields = None;
    let mut link_arity = None;
    let mut effect = None;
    let mut matcher: Option<(String, Pos)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let lead = raw.chars().take_while(|c| c.is_whitespace()).count();
        let body = raw.trim();
        let here = Pos {
            line,
            col: column(lead),
        };
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if let Some(name) = body.strip_prefix('[').and_then(|b| b.strip_suffix(']')) {
            section = name.trim().to_string();
            if !matches!(
                section.as_str(),
                "request_definition" | "policy_definition" | "role_definition" | "policy_effect" | "matchers"
            ) {
                report.refuse(at(file, &here), format!("unknown section `[{section}]`"), None);
            }
            continue;
        }
        let Some((key, value)) = body.split_once('=') else {
            report.refuse(at(file, &here), "expected `name = value`", None);
            continue;
        };
        let key = key.trim();
        let value_col = lead + raw[lead..].find('=').map_or(0, |i| i + 1);
        let value_pos = Pos {
            line,
            col: column(value_col + value.chars().take_while(|c| c.is_whitespace()).count()),
        };
        let value = value.trim();
        match section.as_str() {
            "request_definition" | "policy_definition" => {
                let is_request = section == "request_definition";
                let expected = if is_request { "r" } else { "p" };
                if key != expected {
                    report.refuse(
                        at(file, &here),
                        format!("`{key}` is not read: only `{expected}` is in `[{section}]`"),
                        Some("a model with `r2` or `p2` has no faithful translation"),
                    );
                    continue;
                }
                let mut fields = Vec::new();
                for name in value.split(',').map(str::trim) {
                    match dim_of(name) {
                        Some(dim) if !(is_request && matches!(dim, Dim::Eft | Dim::Priority)) => {
                            fields.push((name.to_string(), dim));
                        }
                        _ => report.refuse(
                            at(file, &value_pos),
                            format!("the field `{name}` is not one this import knows"),
                            Some("fields are named sub, obj, act, dom (and eft, priority in `p`)"),
                        ),
                    }
                }
                let target = if is_request { &mut request } else { &mut policy_fields };
                *target = Some(fields);
            }
            "role_definition" => {
                if key == "g" {
                    let arity = value.split(',').count();
                    if !(2..=3).contains(&arity) || value.split(',').any(|p| p.trim() != "_") {
                        report.refuse(at(file, &value_pos), "`g` is `_, _` or `_, _, _`", None);
                    } else {
                        link_arity = Some(arity);
                    }
                } else {
                    report.refuse(
                        at(file, &here),
                        format!("`{key}` is not read: only `g` is"),
                        Some("a second role definition (`g2`) has no faithful translation"),
                    );
                }
            }
            "policy_effect" => {
                if key != "e" {
                    report.refuse(at(file, &here), format!("`{key}` is not read: only `e` is"), None);
                    continue;
                }
                let squeezed: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                effect = match squeezed.as_str() {
                    "some(where(p.eft==allow))" => Some(Effect::AllowOnly),
                    "!some(where(p.eft==deny))" => Some(Effect::DenyBaseline),
                    "some(where(p.eft==allow))&&!some(where(p.eft==deny))" => Some(Effect::AllowAndDeny),
                    "priority(p.eft)||deny" => Some(Effect::Priority),
                    other => {
                        let why = if other.starts_with("subjectPriority") {
                            "`subjectPriority` orders the lines by the depth of the subject in the role hierarchy, which has no equivalent"
                        } else {
                            "this effect has no faithful translation"
                        };
                        report.refuse(
                            at(file, &value_pos),
                            format!("the effect `{value}` is not read: {why}"),
                            Some("read: some(where (p.eft == allow)), !some(where (p.eft == deny)), some(where (p.eft == allow)) && !some(where (p.eft == deny)), priority(p.eft) || deny"),
                        );
                        None
                    }
                };
            }
            "matchers" => {
                if key != "m" {
                    report.refuse(at(file, &here), format!("`{key}` is not read: only `m` is"), None);
                } else {
                    matcher = Some((value.to_string(), value_pos));
                }
            }
            _ => report.refuse(at(file, &here), "this line is outside any section", None),
        }
    }
    let missing = |name: &str, report: &mut Report| {
        report.refuse(
            Some(Location::new(file, 1, 1, 1)),
            format!("the model has no `{name}`"),
            None,
        );
    };
    if request.is_none() {
        missing("[request_definition]", report);
    }
    if policy_fields.is_none() {
        missing("[policy_definition]", report);
    }
    if effect.is_none() && !report.failed() {
        missing("[policy_effect]", report);
    }
    if matcher.is_none() {
        missing("[matchers]", report);
    }
    if report.failed() {
        return None;
    }
    let (matcher, matcher_at) = matcher?;
    Some(ModelDef {
        request: request?,
        policy: policy_fields?,
        link_arity,
        effect: effect?,
        matcher,
        matcher_at,
        file: file.to_string(),
    })
}

#[derive(Debug, Clone)]
struct Line {
    at: Pos,
    fields: BTreeMap<usize, String>,
    deny: bool,
    priority: i64,
}

#[derive(Debug, Clone)]
struct Link {
    at: Pos,
    member: String,
    role: String,
    domain: Option<String>,
}

#[derive(Debug, Default)]
struct PolicyLines {
    lines: Vec<Line>,
    links: Vec<Link>,
}

fn read_policy(text: &str, options: &Options, def: &ModelDef, report: &mut Report) -> PolicyLines {
    let file = options.policy_file.as_str();
    let records: Vec<Record> = match csv::parse(text) {
        Ok(found) => found,
        Err((line, col, message)) => {
            report.refuse(Some(Location::new(file, line, col, 1)), message, None);
            return PolicyLines::default();
        }
    };
    let mut out = PolicyLines::default();
    for record in records {
        let first = &record.fields[0];
        let place = Pos {
            line: record.line,
            col: first.column,
        };
        let values: Vec<&str> = record.fields.iter().skip(1).map(|f| f.text.as_str()).collect();
        match first.text.as_str() {
            "p" => {
                if values.len() != def.policy.len() {
                    report.refuse(
                        at(file, &place),
                        format!(
                            "the policy line has {} fields, `p` declares {}",
                            values.len(),
                            def.policy.len()
                        ),
                        None,
                    );
                    continue;
                }
                let mut fields = BTreeMap::new();
                let mut deny = false;
                let mut priority = 0;
                for (i, ((_, dim), value)) in def.policy.iter().zip(&values).enumerate() {
                    match dim {
                        Dim::Eft => match *value {
                            "" | "allow" => {}
                            "deny" => deny = true,
                            other => report.refuse(
                                Some(Location::new(file, record.line, record.fields[i + 1].column, 1)),
                                format!("`{other}` is not an effect: use allow or deny"),
                                None,
                            ),
                        },
                        Dim::Priority => match value.parse::<i64>() {
                            Ok(n) => priority = n,
                            Err(_) => report.refuse(
                                Some(Location::new(file, record.line, record.fields[i + 1].column, 1)),
                                format!("`{value}` is not a priority number"),
                                None,
                            ),
                        },
                        _ => {
                            fields.insert(i, (*value).to_string());
                        }
                    }
                }
                out.lines.push(Line {
                    at: place,
                    fields,
                    deny,
                    priority,
                });
            }
            "g" => {
                let Some(arity) = def.link_arity else {
                    report.refuse(
                        at(file, &place),
                        "a `g` line, and the model declares no role definition",
                        None,
                    );
                    continue;
                };
                if values.len() != arity {
                    report.refuse(
                        at(file, &place),
                        format!("the `g` line has {} fields, `g` declares {arity}", values.len()),
                        None,
                    );
                    continue;
                }
                out.links.push(Link {
                    at: place,
                    member: values[0].to_string(),
                    role: values[1].to_string(),
                    domain: values.get(2).map(|d| (*d).to_string()),
                });
            }
            other => report.refuse(
                at(file, &place),
                format!("`{other}` lines are not read: only `p` and `g` are"),
                None,
            ),
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Kind {
    Path(Vec<String>),
    Lit(Value),
    Call(String, Vec<Node>),
    Cmp(Op, Box<Node>, Box<Node>),
    In(Box<Node>, Vec<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    at: Pos,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Num(String),
    Punct(&'static str),
}

struct Lexed {
    toks: Vec<(Tok, Pos)>,
}

fn lex(text: &str, origin: &Pos) -> Result<Lexed, (Pos, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    let place = |i: usize| Pos {
        line: origin.line,
        col: origin.col + u32::try_from(i).unwrap_or(0),
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if c.is_ascii_alphabetic() || c == '_' {
            while chars
                .get(i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            {
                i += 1;
            }
            toks.push((Tok::Word(chars[start..i].iter().collect()), place(start)));
        } else if c.is_ascii_digit() {
            while chars.get(i).is_some_and(|c| c.is_ascii_digit() || *c == '.') {
                i += 1;
            }
            toks.push((Tok::Num(chars[start..i].iter().collect()), place(start)));
        } else if c == '"' || c == '\'' {
            i += 1;
            let mut value = String::new();
            loop {
                match chars.get(i) {
                    None => return Err((place(start), "a string is never closed".to_string())),
                    Some('\\') if chars.get(i + 1).is_some() => {
                        value.push(chars[i + 1]);
                        i += 2;
                    }
                    Some(q) if *q == c => {
                        i += 1;
                        break;
                    }
                    Some(other) => {
                        value.push(*other);
                        i += 1;
                    }
                }
            }
            toks.push((Tok::Str(value), place(start)));
        } else {
            let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
            let punct = match two.as_str() {
                "==" => Some("=="),
                "!=" => Some("!="),
                "<=" => Some("<="),
                ">=" => Some(">="),
                "&&" => Some("&&"),
                "||" => Some("||"),
                _ => None,
            };
            if let Some(p) = punct {
                toks.push((Tok::Punct(p), place(start)));
                i += 2;
                continue;
            }
            let single = match c {
                '<' => "<",
                '>' => ">",
                '!' => "!",
                '(' => "(",
                ')' => ")",
                ',' => ",",
                other => {
                    return Err((
                        place(start),
                        format!(
                            "`{other}` is not read in a matcher: arithmetic and other operators have no translation"
                        ),
                    ));
                }
            };
            toks.push((Tok::Punct(single), place(start)));
            i += 1;
        }
    }
    Ok(Lexed { toks })
}

struct MatcherParser {
    toks: Vec<(Tok, Pos)>,
    at: usize,
    end: Pos,
}

impl MatcherParser {
    fn here(&self) -> Pos {
        self.toks.get(self.at).map_or_else(|| self.end.clone(), |t| t.1.clone())
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|t| &t.0)
    }

    fn eat(&mut self, punct: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(p)) if *p == punct) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Node, (Pos, String)> {
        let mut left = self.and()?;
        while matches!(self.peek(), Some(Tok::Punct("||"))) {
            let at = self.here();
            self.at += 1;
            let right = self.and()?;
            left = Node {
                kind: Kind::Or(Box::new(left), Box::new(right)),
                at,
            };
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Node, (Pos, String)> {
        let mut left = self.cmp()?;
        while matches!(self.peek(), Some(Tok::Punct("&&"))) {
            let at = self.here();
            self.at += 1;
            let right = self.cmp()?;
            left = Node {
                kind: Kind::And(Box::new(left), Box::new(right)),
                at,
            };
        }
        Ok(left)
    }

    fn cmp(&mut self) -> Result<Node, (Pos, String)> {
        let left = self.unary()?;
        let at = self.here();
        let op = match self.peek() {
            Some(Tok::Punct("==")) => Some(Op::Eq),
            Some(Tok::Punct("!=")) => Some(Op::Ne),
            Some(Tok::Punct("<")) => Some(Op::Lt),
            Some(Tok::Punct("<=")) => Some(Op::Le),
            Some(Tok::Punct(">")) => Some(Op::Gt),
            Some(Tok::Punct(">=")) => Some(Op::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.at += 1;
            let right = self.unary()?;
            return Ok(Node {
                kind: Kind::Cmp(op, Box::new(left), Box::new(right)),
                at,
            });
        }
        if matches!(self.peek(), Some(Tok::Word(w)) if w == "in") {
            self.at += 1;
            if !self.eat("(") {
                return Err((self.here(), "expected `(` after `in`".to_string()));
            }
            let mut items = Vec::new();
            loop {
                items.push(self.unary()?);
                if self.eat(",") {
                    continue;
                }
                if self.eat(")") {
                    break;
                }
                return Err((self.here(), "expected `,` or `)` in the list".to_string()));
            }
            return Ok(Node {
                kind: Kind::In(Box::new(left), items),
                at,
            });
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Node, (Pos, String)> {
        let at = self.here();
        if self.eat("!") {
            let inner = self.unary()?;
            return Ok(Node {
                kind: Kind::Not(Box::new(inner)),
                at,
            });
        }
        if self.eat("(") {
            let inner = self.or()?;
            if !self.eat(")") {
                return Err((self.here(), "expected `)`".to_string()));
            }
            return Ok(inner);
        }
        let Some((tok, place)) = self.toks.get(self.at).cloned() else {
            return Err((at, "the matcher ends where an operand was expected".to_string()));
        };
        self.at += 1;
        match tok {
            Tok::Str(s) => Ok(Node {
                kind: Kind::Lit(Value::Str(s)),
                at: place,
            }),
            Tok::Num(n) => {
                let value = n
                    .parse::<i64>()
                    .map(Value::Int)
                    .or_else(|_| n.parse::<f64>().map(Value::Float))
                    .map_err(|_| (place.clone(), format!("`{n}` is not a number")))?;
                Ok(Node {
                    kind: Kind::Lit(value),
                    at: place,
                })
            }
            Tok::Word(w) if w == "true" || w == "false" => Ok(Node {
                kind: Kind::Lit(Value::Bool(w == "true")),
                at: place,
            }),
            Tok::Word(w) => {
                if self.eat("(") {
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.or()?);
                            if self.eat(",") {
                                continue;
                            }
                            if self.eat(")") {
                                break;
                            }
                            return Err((self.here(), "expected `,` or `)` in the arguments".to_string()));
                        }
                    }
                    Ok(Node {
                        kind: Kind::Call(w, args),
                        at: place,
                    })
                } else {
                    Ok(Node {
                        kind: Kind::Path(w.split('.').map(str::to_string).collect()),
                        at: place,
                    })
                }
            }
            Tok::Punct(p) => Err((place, format!("`{p}` where an operand was expected"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SubSpec {
    EqP,
    Lit(String),
    LinkP(bool),
    LinkLit(String, bool),
}

#[derive(Debug, Clone, PartialEq)]
enum ObjSpec {
    EqP,
    KeyP,
    Lit(String),
    KeyLit(String),
}

#[derive(Debug, Clone, PartialEq)]
enum ActSpec {
    EqP,
    RegexP,
    Lit(String),
    RegexLit(String),
}

#[derive(Debug, Clone, PartialEq)]
enum DomSpec {
    EqP,
    Lit(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Atom {
    Sub(SubSpec),
    Obj(ObjSpec),
    Act(ActSpec),
    Dom(DomSpec),
    Cond(Condition),
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Disjunct {
    sub: Option<SubSpec>,
    obj: Option<ObjSpec>,
    act: Option<ActSpec>,
    dom: Option<DomSpec>,
    conds: Vec<Condition>,
}

enum Side {
    R(Dim, Option<String>),
    P(Dim),
    Lit(Value),
}

struct Analyzer<'a> {
    def: &'a ModelDef,
    report: &'a mut Report,
}

impl Analyzer<'_> {
    fn refuse(&mut self, pos: &Pos, message: impl Into<String>, hint: Option<&str>) {
        self.report.refuse(at(&self.def.file, pos), message, hint);
    }

    fn side(&mut self, node: &Node) -> Option<Side> {
        match &node.kind {
            Kind::Lit(v) => Some(Side::Lit(v.clone())),
            Kind::Path(parts) => {
                let (root, field) = (parts[0].as_str(), parts.get(1).map(String::as_str));
                let table = match root {
                    "r" => &self.def.request,
                    "p" => &self.def.policy,
                    _ => {
                        self.refuse(
                            &node.at,
                            format!(
                                "`{}` is not a field of the request (`r.`) or of the policy (`p.`)",
                                parts.join(".")
                            ),
                            None,
                        );
                        return None;
                    }
                };
                let Some(dim) = field.and_then(|f| table.iter().find(|(n, _)| n == f).map(|(_, d)| *d)) else {
                    self.refuse(
                        &node.at,
                        format!("`{}` is not declared in the model", parts.join(".")),
                        None,
                    );
                    return None;
                };
                let attr = (parts.len() > 2).then(|| parts[2..].join("."));
                if root == "p" {
                    if attr.is_some() {
                        self.refuse(&node.at, "a policy field has no attributes", None);
                        return None;
                    }
                    Some(Side::P(dim))
                } else {
                    Some(Side::R(dim, attr))
                }
            }
            _ => {
                self.refuse(&node.at, "this operand has no translation", None);
                None
            }
        }
    }

    fn operand(&mut self, side: &Side, node: &Node) -> Option<Operand> {
        match side {
            Side::Lit(v) => Some(Operand::Lit(v.clone())),
            Side::R(Dim::Sub, attr) | Side::R(Dim::Obj, attr) => {
                let root = if matches!(side, Side::R(Dim::Sub, _)) {
                    "subject"
                } else {
                    "resource"
                };
                match attr {
                    None => Some(Operand::attr(format!("{root}.id"))),
                    Some(name) => {
                        let clean = name
                            .split('.')
                            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
                        if clean {
                            Some(Operand::attr(format!("{root}.{name}")))
                        } else {
                            self.refuse(
                                &node.at,
                                format!("`{name}` is not an attribute name this import can read"),
                                None,
                            );
                            None
                        }
                    }
                }
            }
            _ => {
                self.refuse(
                    &node.at,
                    "the action, the domain and the policy fields are not attributes a condition can compare",
                    Some("the condition language reads attributes of the subject and the resource"),
                );
                None
            }
        }
    }

    fn call(&mut self, name: &str, args: &[Node], node: &Node, negate: bool) -> Option<Atom> {
        if negate {
            self.refuse(
                &node.at,
                format!("`!{name}(...)`: a negated function has no faithful translation"),
                Some("a negation could make the import allow more than the model does"),
            );
            return None;
        }
        match name {
            "g" => {
                let arity = self.def.link_arity;
                let wants_dom = match (args.len(), arity) {
                    (2, Some(2)) => false,
                    (3, Some(3)) => true,
                    (_, None) => {
                        self.refuse(
                            &node.at,
                            "`g` is called, and the model declares no role definition",
                            None,
                        );
                        return None;
                    }
                    _ => {
                        self.refuse(
                            &node.at,
                            "the call of `g` has a different number of arguments than its definition",
                            None,
                        );
                        return None;
                    }
                };
                let first = self.side(&args[0])?;
                if !matches!(first, Side::R(Dim::Sub, None)) {
                    self.refuse(
                        &args[0].at,
                        "the first argument of `g` must be the subject of the request",
                        None,
                    );
                    return None;
                }
                if wants_dom {
                    let third = self.side(&args[2])?;
                    if !matches!(third, Side::R(Dim::Dom, None)) {
                        self.refuse(
                            &args[2].at,
                            "the third argument of `g` must be the domain of the request",
                            None,
                        );
                        return None;
                    }
                }
                match self.side(&args[1])? {
                    Side::P(Dim::Sub) => Some(Atom::Sub(SubSpec::LinkP(wants_dom))),
                    Side::Lit(Value::Str(role)) => Some(Atom::Sub(SubSpec::LinkLit(role, wants_dom))),
                    _ => {
                        self.refuse(
                            &args[1].at,
                            "the second argument of `g` must be `p.sub` or a role name",
                            None,
                        );
                        None
                    }
                }
            }
            "keyMatch" | "regexMatch" if args.len() == 2 => {
                let key = name == "keyMatch";
                let first = self.side(&args[0])?;
                let want = if key { Dim::Obj } else { Dim::Act };
                if !matches!(first, Side::R(d, None) if d == want) {
                    self.refuse(
                        &args[0].at,
                        if key {
                            "the first argument of `keyMatch` must be the object of the request"
                        } else {
                            "`regexMatch` is read on the action of the request only"
                        },
                        None,
                    );
                    return None;
                }
                match self.side(&args[1])? {
                    Side::P(d) if d == want => Some(if key {
                        Atom::Obj(ObjSpec::KeyP)
                    } else {
                        Atom::Act(ActSpec::RegexP)
                    }),
                    Side::Lit(Value::Str(p)) => Some(if key {
                        Atom::Obj(ObjSpec::KeyLit(p))
                    } else {
                        Atom::Act(ActSpec::RegexLit(p))
                    }),
                    _ => {
                        self.refuse(
                            &args[1].at,
                            "the second argument must be the matching policy field or a string",
                            None,
                        );
                        None
                    }
                }
            }
            "keyMatch2" | "keyMatch3" | "keyMatch4" | "keyMatch5" | "keyGet" | "keyGet2" | "regexMatch"
            | "globMatch" | "ipMatch" | "timeMatch" => {
                self.refuse(
                    &node.at,
                    format!("`{name}` has no faithful translation: conditions have no regular expressions, path parameters or globs"),
                    Some("only `keyMatch` (a `*` suffix) and `regexMatch` over alternations of literals are read"),
                );
                None
            }
            other => {
                self.refuse(&node.at, format!("the function `{other}` has no translation"), None);
                None
            }
        }
    }

    fn comparison(&mut self, op: Op, left: &Node, right: &Node, node: &Node, negate: bool) -> Option<Atom> {
        let op = if negate {
            match op {
                Op::Eq => Op::Ne,
                Op::Ne => Op::Eq,
                Op::Lt => Op::Ge,
                Op::Le => Op::Gt,
                Op::Gt => Op::Le,
                Op::Ge => Op::Lt,
            }
        } else {
            op
        };
        let (a, b) = (self.side(left)?, self.side(right)?);
        let (a, b, left, right) = if matches!(a, Side::P(_) | Side::Lit(_)) && matches!(b, Side::R(..)) {
            (b, a, right, left)
        } else {
            (a, b, left, right)
        };
        match (&a, &b) {
            (Side::R(d, None), Side::P(p)) if d == p && op == Op::Eq => match d {
                Dim::Sub => Some(Atom::Sub(SubSpec::EqP)),
                Dim::Obj => Some(Atom::Obj(ObjSpec::EqP)),
                Dim::Act => Some(Atom::Act(ActSpec::EqP)),
                Dim::Dom => Some(Atom::Dom(DomSpec::EqP)),
                _ => None,
            },
            (Side::R(_, _), Side::P(_)) | (Side::P(_), _) => {
                self.refuse(
                    &node.at,
                    "only `r.x == p.x` between the request and the policy is read",
                    Some("anything else (a different field, `!=`, an order) has no faithful translation"),
                );
                None
            }
            (Side::R(d @ (Dim::Sub | Dim::Obj | Dim::Act | Dim::Dom), None), Side::Lit(Value::Str(s)))
                if op == Op::Eq =>
            {
                let s = s.clone();
                match d {
                    Dim::Sub => Some(Atom::Sub(SubSpec::Lit(s))),
                    Dim::Obj => Some(Atom::Obj(ObjSpec::Lit(s))),
                    Dim::Act => Some(Atom::Act(ActSpec::Lit(s))),
                    _ => Some(Atom::Dom(DomSpec::Lit(s))),
                }
            }
            (Side::R(Dim::Act | Dim::Dom, None), _) => {
                self.refuse(&node.at, "the action and the domain are compared with `==` only", None);
                None
            }
            _ => {
                let l = self.operand(&a, left)?;
                let r = self.operand(&b, right)?;
                Some(Atom::Cond(match op {
                    Op::Eq => Condition::eq(l, r),
                    Op::Ne => Condition::ne(l, r),
                    Op::Lt => Condition::lt(l, r),
                    Op::Le => Condition::le(l, r),
                    Op::Gt => Condition::gt(l, r),
                    Op::Ge => Condition::ge(l, r),
                }))
            }
        }
    }

    fn membership(&mut self, item: &Node, set: &[Node], node: &Node, negate: bool) -> Option<Atom> {
        let side = self.side(item)?;
        let item = self.operand(&side, item)?;
        let mut values = Vec::new();
        for entry in set {
            match &entry.kind {
                Kind::Lit(v) => values.push(v.clone()),
                _ => {
                    self.refuse(&entry.at, "the list of `in` holds literals only", None);
                    return None;
                }
            }
        }
        let cond = Condition::In {
            item,
            set: Operand::Lit(Value::List(values)),
        };
        let _ = node;
        Some(Atom::Cond(if negate { Condition::not(cond) } else { cond }))
    }

    fn dnf(&mut self, node: &Node, negate: bool) -> Option<Vec<Vec<Atom>>> {
        match &node.kind {
            Kind::And(a, b) | Kind::Or(a, b) => {
                let is_and = matches!(node.kind, Kind::And(..)) != negate;
                let left = self.dnf(a, negate)?;
                let right = self.dnf(b, negate)?;
                if is_and {
                    if left.len().saturating_mul(right.len()) > MAX_DISJUNCTS {
                        self.refuse(
                            &node.at,
                            format!("the matcher expands to more than {MAX_DISJUNCTS} alternatives"),
                            None,
                        );
                        return None;
                    }
                    let mut out = Vec::new();
                    for l in &left {
                        for r in &right {
                            out.push(l.iter().chain(r).cloned().collect());
                        }
                    }
                    Some(out)
                } else {
                    let mut all = left;
                    all.extend(right);
                    if all.len() > MAX_DISJUNCTS {
                        self.refuse(
                            &node.at,
                            format!("the matcher expands to more than {MAX_DISJUNCTS} alternatives"),
                            None,
                        );
                        return None;
                    }
                    Some(all)
                }
            }
            Kind::Not(inner) => self.dnf(inner, !negate),
            Kind::Cmp(op, l, r) => self.comparison(*op, l, r, node, negate).map(|a| vec![vec![a]]),
            Kind::In(item, set) => self.membership(item, set, node, negate).map(|a| vec![vec![a]]),
            Kind::Call(name, args) => self.call(name, args, node, negate).map(|a| vec![vec![a]]),
            Kind::Path(_) | Kind::Lit(_) => {
                self.refuse(&node.at, "a bare value is not a condition", None);
                None
            }
        }
    }

    fn merge(&mut self, atoms: Vec<Atom>, node: &Node) -> Option<Disjunct> {
        let mut d = Disjunct::default();
        let clash = |what: &str, this: &mut Self| {
            this.refuse(
                &node.at,
                format!("one alternative of the matcher constrains the {what} twice"),
                Some("two constraints on the same field have no faithful translation"),
            );
        };
        for atom in atoms {
            match atom {
                Atom::Sub(s) => {
                    if d.sub.replace(s).is_some() {
                        clash("subject", self);
                        return None;
                    }
                }
                Atom::Obj(o) => {
                    if d.obj.replace(o).is_some() {
                        clash("object", self);
                        return None;
                    }
                }
                Atom::Act(a) => {
                    if d.act.replace(a).is_some() {
                        clash("action", self);
                        return None;
                    }
                }
                Atom::Dom(m) => {
                    if d.dom.replace(m).is_some() {
                        clash("domain", self);
                        return None;
                    }
                }
                Atom::Cond(c) => d.conds.push(c),
            }
        }
        Some(d)
    }
}

fn analyze(def: &ModelDef, report: &mut Report) -> Vec<Disjunct> {
    let lexed = match lex(&def.matcher, &def.matcher_at) {
        Ok(found) => found,
        Err((pos, message)) => {
            report.refuse(at(&def.file, &pos), message, None);
            return Vec::new();
        }
    };
    let mut parser = MatcherParser {
        toks: lexed.toks,
        at: 0,
        end: def.matcher_at.clone(),
    };
    let tree = parser.or().and_then(|tree| {
        if parser.at < parser.toks.len() {
            Err((parser.here(), "unexpected text after the matcher".to_string()))
        } else {
            Ok(tree)
        }
    });
    let tree = match tree {
        Ok(found) => found,
        Err((pos, message)) => {
            report.refuse(at(&def.file, &pos), message, None);
            return Vec::new();
        }
    };
    let mut analyzer = Analyzer { def, report };
    let Some(alternatives) = analyzer.dnf(&tree, false) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for atoms in alternatives {
        match analyzer.merge(atoms, &tree) {
            Some(d) => out.push(d),
            None => return Vec::new(),
        }
    }
    out
}

fn object_target(id: String) -> (TargetSelector, Option<Condition>) {
    if is_name(&id) {
        (TargetSelector::exact(OBJECT, id), None)
    } else {
        (
            TargetSelector::kind(OBJECT),
            Some(Condition::eq(Operand::attr("resource.id"), Operand::lit(id))),
        )
    }
}

fn key_match_condition(pattern: &str) -> Option<Condition> {
    let star = pattern.find('*')?;
    let prefix = &pattern[..star];
    (!prefix.is_empty()).then(|| Condition::starts_with(Operand::attr("resource.id"), Operand::lit(prefix.to_string())))
}

fn regex_acts(pattern: &str, domain: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let mut body = pattern;
    let start = body.strip_prefix('^');
    let anchored_start = start.is_some();
    body = start.unwrap_or(body);
    let end = body.strip_suffix('$');
    let anchored_end = end.is_some();
    body = end.unwrap_or(body);
    if anchored_start != anchored_end {
        return Err("an anchor on one side only binds one alternative, not the whole pattern".to_string());
    }
    if body == ".*" {
        return Ok(domain.iter().cloned().collect());
    }
    let mut alternatives: Vec<String> = Vec::new();
    let mut depth = 0_i32;
    let mut current = String::new();
    let mut parts = Vec::new();
    for c in body.chars() {
        match c {
            '(' => {
                depth += 1;
                current.push(c);
            }
            ')' => {
                depth -= 1;
                current.push(c);
            }
            '|' if depth == 0 => parts.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    parts.push(current);
    for part in parts {
        let inner = part
            .strip_prefix('(')
            .and_then(|p| p.strip_suffix(')'))
            .filter(|p| !p.contains('('));
        let literals: Vec<&str> = match inner {
            Some(group) => group.split('|').collect(),
            None => vec![part.as_str()],
        };
        for literal in literals {
            if literal.is_empty() || literal.chars().any(|c| ".*+?[]{}\\()^$|".contains(c)) {
                return Err(format!(
                    "`{pattern}` is a regular expression beyond alternations of literals"
                ));
            }
            alternatives.push(literal.to_string());
        }
    }
    Ok(domain
        .iter()
        .filter(|act| {
            alternatives.iter().any(|alt| {
                if anchored_start {
                    *act == alt
                } else {
                    act.contains(alt.as_str())
                }
            })
        })
        .cloned()
        .collect())
}

fn field(def: &ModelDef, line: &Line, dim: Dim) -> Option<String> {
    def.policy
        .iter()
        .position(|(_, d)| *d == dim)
        .and_then(|i| line.fields.get(&i).cloned())
}

#[derive(PartialEq, Eq, Clone)]
struct GrantKey {
    subject: String,
    permission: String,
    target: String,
    effect: bool,
    scope: String,
    condition: String,
}

fn build(
    def: &ModelDef,
    pl: &PolicyLines,
    disjuncts: &[Disjunct],
    options: &Options,
    report: &mut Report,
) -> Option<(Policy, BTreeMap<String, String>)> {
    let file = def.file.as_str();
    let model_at = || at(file, &def.matcher_at);
    let uses_domain = def.request.iter().any(|(_, d)| *d == Dim::Dom);
    let domain_links = def.link_arity == Some(3);

    let mut lines = pl.lines.clone();
    let has_priority = def.policy.iter().any(|(_, d)| *d == Dim::Priority);
    if def.effect == Effect::Priority && has_priority {
        lines.sort_by_key(|l| l.priority);
    }
    let virtual_line = lines.is_empty();
    if virtual_line {
        lines.push(Line {
            at: def.matcher_at.clone(),
            fields: BTreeMap::new(),
            deny: false,
            priority: 0,
        });
    }

    let mut domain: BTreeSet<String> = options.actions.iter().cloned().collect();
    for line in &pl.lines {
        if let Some(act) = field(def, line, Dim::Act) {
            domain.insert(act);
        }
    }
    for d in disjuncts {
        match &d.act {
            Some(ActSpec::Lit(a)) => {
                domain.insert(a.clone());
            }
            Some(ActSpec::RegexLit(p)) => {
                if let Ok(names) = literal_names(p) {
                    domain.extend(names);
                }
            }
            _ => {}
        }
    }
    for line in &pl.lines {
        if let Some(act) = field(def, line, Dim::Act) {
            if disjuncts.iter().any(|d| d.act == Some(ActSpec::RegexP)) {
                if let Ok(names) = literal_names(&act) {
                    domain.extend(names);
                }
            }
        }
    }
    let needs_any_action = disjuncts.iter().any(|d| d.act.is_none()) || def.effect == Effect::DenyBaseline;
    if needs_any_action && domain.is_empty() {
        report.refuse(
            model_at(),
            "the model does not constrain the action and the policy names none",
            Some("name the actions with `--action <name>` (repeatable)"),
        );
        return None;
    }

    let role_names: BTreeSet<&str> = pl.links.iter().map(|l| l.role.as_str()).collect();
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    let mut taken: BTreeMap<String, String> = BTreeMap::new();
    for act in &domain {
        let key = format!("{OBJECT}.{}", key_segment(act));
        if let Some(other) = taken.get(&key) {
            report.refuse(
                model_at(),
                format!("the actions `{other}` and `{act}` both become the permission `{key}`"),
                Some("permission keys are lowercase letters, digits and `_`"),
            );
            return None;
        }
        taken.insert(key.clone(), act.clone());
        keys.insert(act.clone(), key);
    }

    let mut ids = BTreeSet::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut seen: Vec<GrantKey> = Vec::new();
    let mut dropped_deny = 0_usize;
    let mut dropped_allow = 0_usize;
    let mut dropped_at: Option<Location> = None;
    let mut line_count = 0;

    if def.effect == Effect::DenyBaseline {
        for act in &domain {
            grants.push(Grant::allow(
                unique_id(&format!("casbin_default_{}", key_segment(act)), &mut ids),
                SubjectMatcher::Any,
                keys[act].clone(),
                TargetSelector::kind(OBJECT),
            ));
        }
    }

    for line in &lines {
        if !virtual_line {
            line_count += 1;
        }
        let deny = line.deny;
        match (def.effect, deny) {
            (Effect::AllowOnly, true) => {
                dropped_deny += 1;
                dropped_at.get_or_insert_with(|| at(&options.policy_file, &line.at).expect("a location"));
                continue;
            }
            (Effect::DenyBaseline, false) if !virtual_line => {
                dropped_allow += 1;
                continue;
            }
            _ => {}
        }
        for d in disjuncts {
            let acts: Vec<String> = match &d.act {
                Some(ActSpec::EqP) => match field(def, line, Dim::Act) {
                    Some(a) => vec![a],
                    None => continue,
                },
                Some(ActSpec::Lit(a)) => vec![a.clone()],
                Some(ActSpec::RegexP | ActSpec::RegexLit(_)) => {
                    let pattern = match &d.act {
                        Some(ActSpec::RegexLit(p)) => p.clone(),
                        _ => field(def, line, Dim::Act).unwrap_or_default(),
                    };
                    match regex_acts(&pattern, &domain) {
                        Ok(found) => found,
                        Err(why) => {
                            report.refuse(
                                at(&options.policy_file, &line.at),
                                why,
                                Some("only alternations of literals and `.*` are read"),
                            );
                            return None;
                        }
                    }
                }
                None => domain.iter().cloned().collect(),
            };
            let (target, key_condition) = match &d.obj {
                Some(ObjSpec::EqP) => match field(def, line, Dim::Obj) {
                    Some(o) => object_target(o),
                    None => continue,
                },
                Some(ObjSpec::Lit(o)) => object_target(o.clone()),
                Some(spec @ (ObjSpec::KeyP | ObjSpec::KeyLit(_))) => {
                    let pattern = match spec {
                        ObjSpec::KeyLit(p) => p.clone(),
                        _ => field(def, line, Dim::Obj).unwrap_or_default(),
                    };
                    if pattern.contains('*') {
                        (TargetSelector::kind(OBJECT), key_match_condition(&pattern))
                    } else {
                        object_target(pattern)
                    }
                }
                None => (TargetSelector::kind(OBJECT), None),
            };
            let mut matchers: Vec<SubjectMatcher> = Vec::new();
            match &d.sub {
                Some(SubSpec::EqP) => match field(def, line, Dim::Sub) {
                    Some(s) => matchers.push(SubjectMatcher::user(s)),
                    None => continue,
                },
                Some(SubSpec::Lit(s)) => matchers.push(SubjectMatcher::user(s.clone())),
                Some(SubSpec::LinkP(_)) => match field(def, line, Dim::Sub) {
                    Some(s) if role_names.contains(s.as_str()) => matchers.push(SubjectMatcher::role(s)),
                    Some(s) => matchers.push(SubjectMatcher::user(s)),
                    None => continue,
                },
                Some(SubSpec::LinkLit(role, _)) => {
                    matchers.push(SubjectMatcher::role(role.clone()));
                }
                None => matchers.push(SubjectMatcher::Any),
            }
            let scope = match &d.dom {
                Some(DomSpec::EqP) => field(def, line, Dim::Dom).map(|v| Anchor::new(DOMAIN, v)),
                Some(DomSpec::Lit(v)) => Some(Anchor::new(DOMAIN, v.clone())),
                None => None,
            };
            let mut conds = d.conds.clone();
            conds.extend(key_condition);
            let condition = match conds.len() {
                0 => None,
                1 => conds.pop(),
                _ => Some(Condition::all(conds)),
            };
            for matcher in matchers {
                for act in &acts {
                    let Some(permission) = keys.get(act) else { continue };
                    let probe = GrantKey {
                        subject: format!("{matcher:?}"),
                        permission: permission.clone(),
                        target: format!("{target:?}"),
                        effect: deny,
                        scope: format!("{scope:?}"),
                        condition: format!("{condition:?}"),
                    };
                    if seen.contains(&probe) {
                        continue;
                    }
                    seen.push(probe);
                    let id = unique_id(&format!("casbin_{}", line.at.line), &mut ids);
                    let mut grant = Grant::new(
                        id,
                        if deny {
                            crate::Effect::Deny
                        } else {
                            crate::Effect::Allow
                        },
                        matcher.clone(),
                        permission.clone(),
                        target.clone(),
                    );
                    if let Some(scope) = scope.clone() {
                        grant = grant.scoped(scope);
                    }
                    if let Some(condition) = condition.clone() {
                        grant = grant.when(condition);
                    }
                    grants.push(grant);
                }
            }
        }
    }
    if dropped_deny > 0 {
        report.note(
            dropped_at,
            format!(
                "{dropped_deny} policy line(s) with the effect deny dropped: `some(where (p.eft == allow))` ignores them"
            ),
        );
    }
    if dropped_allow > 0 {
        report.note(
            model_at(),
            format!(
                "{dropped_allow} policy line(s) with the effect allow dropped: under `!some(where (p.eft == deny))` everything not denied is allowed already"
            ),
        );
    }
    if needs_any_action {
        report.note(
            model_at(),
            format!(
                "the action is not constrained: expanded over the {} action(s) known ({}); a request for another action is denied",
                domain.len(),
                domain.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    if disjuncts
        .iter()
        .any(|d| matches!(d.act, Some(ActSpec::RegexP | ActSpec::RegexLit(_))))
    {
        report.note(
            model_at(),
            "`regexMatch` on the action is expanded over the actions the policy names; a request for another action is denied",
        );
    }

    let mut policy = Policy::default();
    let mut kinds = vec![OBJECT.to_string()];
    if uses_domain || domain_links || grants.iter().any(|g| g.scope.is_some()) {
        kinds.push(DOMAIN.to_string());
    }
    policy.catalog = CatalogExport {
        target_kinds: kinds,
        broad_targets: Vec::new(),
        permissions: keys
            .values()
            .map(|k| PermissionDef::new(k.clone()).targets([OBJECT]))
            .collect(),
    };
    policy.strategy = match def.effect {
        Effect::AllowOnly => StrategySpec::MostSpecific,
        Effect::DenyBaseline | Effect::AllowAndDeny => StrategySpec::DenyOverrides,
        Effect::Priority => StrategySpec::FirstApplicable,
    };

    let mut inherits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut subjects: BTreeMap<String, Subject> = BTreeMap::new();
    let mut graph_edges = 0;
    let mut assignments = 0;
    for link in &pl.links {
        if role_names.contains(link.member.as_str()) {
            if link.domain.is_some() {
                report.refuse(
                    at(&options.policy_file, &link.at),
                    format!(
                        "`{}` inherits `{}` only inside a domain: the role graph has no per-domain edges",
                        link.member, link.role
                    ),
                    Some("an inheritance that depends on the domain has no faithful translation"),
                );
                return None;
            }
            let parents = inherits.entry(link.member.clone()).or_default();
            if !parents.contains(&link.role) {
                parents.push(link.role.clone());
                graph_edges += 1;
            }
        } else {
            let subject = subjects
                .entry(link.member.clone())
                .or_insert_with(|| Subject::of_kind("user", link.member.clone()));
            let assignment = match &link.domain {
                Some(d) => RoleAssignment::in_scope(link.role.clone(), Anchor::new(DOMAIN, d.clone())),
                None => RoleAssignment::new(link.role.clone()),
            };
            if !subject.roles.contains(&assignment) {
                subject.roles.push(assignment);
                assignments += 1;
            }
        }
    }
    for role in &role_names {
        inherits.entry((*role).to_string()).or_default();
    }
    policy.roles = inherits
        .into_iter()
        .map(|(role, inherits)| RoleSpec { role, inherits })
        .collect();
    policy.subjects = subjects.into_values().collect();
    policy.grants = grants;
    report.converted(line_count, "policy lines (`p`)");
    report.converted(policy.grants.len(), "grants");
    report.converted(assignments, "role assignments (`g`, as subjects)");
    report.converted(graph_edges, "role inheritances (`g` between roles)");
    report.converted(disjuncts.len(), "matcher alternative(s)");
    report.converted(keys.len(), "permissions, one per action");
    Some((policy, keys))
}

fn literal_names(pattern: &str) -> Result<Vec<String>, ()> {
    let body = pattern.strip_prefix('^').unwrap_or(pattern);
    let body = body.strip_suffix('$').unwrap_or(body);
    let mut names = Vec::new();
    for part in body.split('|') {
        let part = part.trim_matches(['(', ')']);
        if part.is_empty() || part.chars().any(|c| ".*+?[]{}\\()^$".contains(c)) {
            return Err(());
        }
        names.push(part.to_string());
    }
    Ok(names)
}
