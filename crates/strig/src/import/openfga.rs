//! OpenFGA: a model (the DSL or the JSON) and its tuples, read into a [`Policy`].
//!
//! Each type with relations becomes a target kind and each relation a [`RelationSpec`] whose
//! [`Rewrite`] is the OpenFGA userset rewrite (`This`, `Computed`, `TupleToUserset`, `Union`,
//! `Intersection`, `Exclusion`). Each relation also becomes a permission `<type>.<relation>` and
//! one grant that allows whoever has the relation, so `check(user, relation, object)` in OpenFGA is
//! `check(user, "<type>.<relation>", object)` here ([`OpenFgaImport::request`]). The tuples go to
//! `Policy::tuples`.
//!
//! OpenFGA conditions (CEL) are not translated: a relation that accepts `user with condition` and a
//! tuple that carries a condition are errors, not tuples read as unconditional.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as Json;

use super::csv::{self, column, line_number};
use super::{ImportError, Report, finish, key_segment, unique_id};
use crate::dsl::{Location, Policy};
use crate::{
    CatalogExport, Grant, ObjectRef, PermissionDef, RelationSpec, Resource, Rewrite, Subject, SubjectMatcher,
    TargetSelector, Tuple, TupleSubject,
};

/// Names used in positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Name of the model, in positions.
    pub model_file: String,
    /// Name of the tuples, in positions.
    pub tuples_file: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            model_file: "model.fga".to_string(),
            tuples_file: "tuples".to_string(),
        }
    }
}

/// An OpenFGA model and tuples, imported.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct OpenFgaImport {
    policy: Policy,
    report: Report,
    keys: BTreeMap<(String, String), String>,
}

impl OpenFgaImport {
    /// The policy: catalog, relations, grants and tuples.
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

    /// The permission key of `relation` on `object_type`.
    pub fn permission(&self, object_type: &str, relation: &str) -> Option<&str> {
        self.keys
            .get(&(object_type.to_string(), relation.to_string()))
            .map(String::as_str)
    }

    /// The Strig request that answers the OpenFGA check `user`, `relation`, `object`
    /// (`user:anne`, `viewer`, `document:roadmap`): the subject, the permission key and the resource.
    /// `None` when `object` is not `type:id`, `user` is not an object (`type:id`) or the relation
    /// does not exist on the type.
    pub fn request(&self, user: &str, relation: &str, object: &str) -> Option<(Subject, String, Resource)> {
        let (kind, id) = object.split_once(':')?;
        let (user_kind, user_id) = user.split_once(':')?;
        let permission = self.permission(kind, relation)?.to_string();
        Some((
            Subject::of_kind(user_kind, user_id),
            permission,
            Resource::new(kind, id),
        ))
    }
}

/// Reads an OpenFGA model and tuples.
///
/// The model is the JSON when it starts with `{`, otherwise the DSL. The tuples are JSON (an array,
/// or an object with `tuples`, `tuple_keys` or `writes.tuple_keys`), CSV with the header of the
/// OpenFGA CLI (`user_type,user_id,user_relation,relation,object_type,object_id`), a YAML list of
/// `user`/`relation`/`object`, or one `object#relation@user` per line. An empty `tuples` is fine.
///
/// # Errors
/// [`ImportError`] when the model or a tuple is malformed or has no faithful translation (a
/// condition, a module, an operator mix without parentheses), each with its position and reason.
pub fn import(model: &str, tuples: &str, options: &Options) -> Result<OpenFgaImport, ImportError> {
    let mut report = Report::default();
    let parsed = if model.trim_start().starts_with('{') {
        json_model(model, options, &mut report)
    } else {
        dsl_model(model, options, &mut report)
    };
    let Some(types) = parsed else {
        return Err(ImportError { report });
    };
    let mut policy = Policy::default();
    let mut keys: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut taken: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut kinds = Vec::new();
    let mut permissions = Vec::new();
    let mut relations = Vec::new();
    let mut grants = Vec::new();
    for ty in &types {
        if ty.relations.is_empty() {
            continue;
        }
        kinds.push(ty.name.clone());
        for relation in &ty.relations {
            let key = format!("{}.{}", key_segment(&ty.name), key_segment(&relation.name));
            if let Some(other) = taken.get(&key) {
                report.refuse(
                    relation.at.clone(),
                    format!(
                        "`{}#{}` and `{}#{}` both become the permission `{key}`",
                        ty.name, relation.name, other.0, other.1
                    ),
                    Some("rename one of them: permission keys are lowercase letters, digits and `_`"),
                );
                continue;
            }
            taken.insert(key.clone(), (ty.name.clone(), relation.name.clone()));
            keys.insert((ty.name.clone(), relation.name.clone()), key.clone());
            permissions.push(PermissionDef::new(key.clone()).targets([ty.name.as_str()]));
            relations.push(RelationSpec {
                kind: ty.name.clone(),
                relation: relation.name.clone(),
                rewrite: relation.rewrite.clone(),
            });
            grants.push(Grant::allow(
                unique_id(&format!("{}_{}", ty.name, relation.name), &mut ids),
                SubjectMatcher::relation(relation.name.clone()),
                key,
                TargetSelector::kind(ty.name.clone()),
            ));
        }
    }
    report.converted(kinds.len(), "types with relations (target kinds)");
    report.converted(relations.len(), "relations (rewrites)");
    report.converted(permissions.len(), "permissions, one per relation");
    report.converted(grants.len(), "grants, one per relation");
    policy.catalog = CatalogExport {
        target_kinds: kinds,
        broad_targets: Vec::new(),
        permissions,
    };
    policy.relations = Some(relations);
    policy.grants = grants;
    let defined: BTreeSet<(String, String)> = keys.keys().cloned().collect();
    policy.tuples = read_tuples(tuples, options, &defined, &mut report);
    report.converted(policy.tuples.len(), "tuples");
    if report.failed() {
        return Err(ImportError { report });
    }
    let policy = policy.canonical();
    finish(&policy, &mut report);
    if report.failed() {
        return Err(ImportError { report });
    }
    Ok(OpenFgaImport { policy, report, keys })
}

#[derive(Debug, Clone)]
struct TypeDef {
    name: String,
    relations: Vec<RelationDef>,
}

#[derive(Debug, Clone)]
struct RelationDef {
    name: String,
    rewrite: Rewrite,
    at: Option<Location>,
}

#[derive(Debug, Clone)]
enum Expr {
    This,
    Computed(String),
    FromParent { tupleset: String, computed: String },
    Union(Vec<Expr>),
    Intersection(Vec<Expr>),
    Difference(Box<Expr>, Box<Expr>),
}

impl Expr {
    fn lower(&self) -> Rewrite {
        match self {
            Expr::This => Rewrite::This,
            Expr::Computed(relation) => Rewrite::computed(relation.clone()),
            Expr::FromParent { tupleset, computed } => Rewrite::from_parent(tupleset.clone(), computed.clone()),
            Expr::Union(of) => Rewrite::union(of.iter().map(Expr::lower)),
            Expr::Intersection(of) => Rewrite::intersection(of.iter().map(Expr::lower)),
            Expr::Difference(base, subtract) => Rewrite::exclusion(base.lower(), subtract.lower()),
        }
    }
}

struct Parser<'a> {
    chars: Vec<char>,
    at: usize,
    line: u32,
    base: usize,
    file: &'a str,
    owner: String,
    relation: String,
    conditions: Vec<(String, u32)>,
}

type Failure = (u32, String);

impl Parser<'_> {
    fn col(&self) -> u32 {
        column(self.at + self.base)
    }

    fn fail<T>(&self, message: impl Into<String>) -> Result<T, Failure> {
        Err((self.col(), message.into()))
    }

    fn skip(&mut self) {
        while self.chars.get(self.at).is_some_and(|c| c.is_whitespace()) {
            self.at += 1;
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.skip();
        self.chars.get(self.at).copied()
    }

    fn word(&mut self) -> Option<String> {
        self.skip();
        let start = self.at;
        while self
            .chars
            .get(self.at)
            .is_some_and(|c| !c.is_whitespace() && !matches!(c, '(' | ')' | '[' | ']' | ','))
        {
            self.at += 1;
        }
        (self.at > start).then(|| self.chars[start..self.at].iter().collect())
    }

    fn peek_word(&mut self) -> Option<String> {
        let saved = self.at;
        let word = self.word();
        self.at = saved;
        word
    }

    fn expr(&mut self) -> Result<Expr, Failure> {
        let first = self.primary()?;
        match self.peek_word().as_deref() {
            Some("or") => {
                let mut of = vec![first];
                while self.peek_word().as_deref() == Some("or") {
                    self.word();
                    of.push(self.primary()?);
                }
                self.no_mix()?;
                Ok(Expr::Union(of))
            }
            Some("and") => {
                let mut of = vec![first];
                while self.peek_word().as_deref() == Some("and") {
                    self.word();
                    of.push(self.primary()?);
                }
                self.no_mix()?;
                Ok(Expr::Intersection(of))
            }
            Some("but") => {
                self.word();
                if self.word().as_deref() != Some("not") {
                    return self.fail("expected `not` after `but`");
                }
                let subtract = self.primary()?;
                self.no_mix()?;
                Ok(Expr::Difference(Box::new(first), Box::new(subtract)))
            }
            _ => Ok(first),
        }
    }

    fn no_mix(&mut self) -> Result<(), Failure> {
        match self.peek_word().as_deref() {
            Some("or" | "and" | "but") => {
                self.fail("`or`, `and` and `but not` do not mix without parentheses: group them with `( )`")
            }
            _ => Ok(()),
        }
    }

    fn primary(&mut self) -> Result<Expr, Failure> {
        match self.peek() {
            Some('(') => {
                self.at += 1;
                let inner = self.expr()?;
                if self.peek() != Some(')') {
                    return self.fail("expected `)`");
                }
                self.at += 1;
                Ok(inner)
            }
            Some('[') => {
                let open = self.col();
                self.at += 1;
                let start = self.at;
                while self.chars.get(self.at).is_some_and(|c| *c != ']') {
                    self.at += 1;
                }
                if self.chars.get(self.at).is_none() {
                    return Err((open, "the list of types is never closed".to_string()));
                }
                let inside: String = self.chars[start..self.at].iter().collect();
                self.at += 1;
                for entry in inside.split(',') {
                    let entry = entry.trim();
                    if let Some((_, condition)) = entry.split_once(" with ") {
                        self.conditions.push((condition.trim().to_string(), open));
                    }
                }
                Ok(Expr::This)
            }
            Some(_) => {
                let Some(name) = self.word() else {
                    return self.fail("expected a relation");
                };
                if self.peek_word().as_deref() == Some("from") {
                    self.word();
                    let Some(parent) = self.word() else {
                        return self.fail("expected the relation that points to the parent after `from`");
                    };
                    return Ok(Expr::FromParent {
                        tupleset: parent,
                        computed: name,
                    });
                }
                Ok(Expr::Computed(name))
            }
            None => self.fail("the definition is empty"),
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let mut previous_space = true;
    for (at, c) in line.char_indices() {
        if c == '#' && previous_space {
            return &line[..at];
        }
        previous_space = c.is_whitespace();
    }
    line
}

fn dsl_model(text: &str, options: &Options, report: &mut Report) -> Option<Vec<TypeDef>> {
    let file = options.model_file.as_str();
    let mut types: Vec<TypeDef> = Vec::new();
    let mut seen_types = BTreeSet::new();
    let mut in_relations = false;
    let mut skipping_condition = 0_usize;
    let mut found_any = false;
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let body = strip_comment(raw);
        let trimmed = body.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lead = body.chars().take_while(|c| c.is_whitespace()).count();
        let here = |col: usize| Location::new(file, line, column(col), 1);
        if skipping_condition > 0 {
            skipping_condition = skipping_condition
                .saturating_add(trimmed.matches('{').count())
                .saturating_sub(trimmed.matches('}').count());
            continue;
        }
        let mut words = trimmed.split_whitespace();
        match words.next() {
            Some("model") => {}
            Some("schema") => {
                if words.next().is_some_and(|v| v != "1.1") {
                    report.refuse(
                        Some(here(lead)),
                        "only the schema 1.1 is read",
                        Some("migrate the model to 1.1 with the OpenFGA CLI"),
                    );
                }
            }
            Some("module" | "extend") => report.refuse(
                Some(here(lead)),
                "modules (`module`, `extend type`) are not read",
                Some("flatten the model into one file first (`fga model transform`)"),
            ),
            Some("condition") => {
                report.refuse(
                    Some(here(lead)),
                    "OpenFGA conditions (CEL) are not translated",
                    Some("replace the condition with a relation, or write the condition as a Strig grant condition by hand"),
                );
                skipping_condition = trimmed
                    .matches('{')
                    .count()
                    .saturating_sub(trimmed.matches('}').count());
            }
            Some("type") => {
                let Some(name) = words.next() else {
                    report.refuse(Some(here(lead)), "a `type` needs a name", None);
                    continue;
                };
                if !seen_types.insert(name.to_string()) {
                    report.refuse(
                        Some(here(lead + 5)),
                        format!("the type `{name}` is declared twice"),
                        None,
                    );
                }
                in_relations = false;
                found_any = true;
                types.push(TypeDef {
                    name: name.to_string(),
                    relations: Vec::new(),
                });
            }
            Some("relations") => in_relations = true,
            Some("define") if in_relations && !types.is_empty() => {
                let Some(colon) = trimmed.find(':') else {
                    report.refuse(Some(here(lead)), "a `define` needs `name: definition`", None);
                    continue;
                };
                let name = trimmed["define".len()..colon].trim().to_string();
                let rest_start = lead + colon + 1;
                let mut parser = Parser {
                    chars: body.chars().skip(rest_start).collect(),
                    at: 0,
                    line,
                    base: rest_start,
                    file,
                    owner: types.last().map(|t| t.name.clone()).unwrap_or_default(),
                    relation: name.clone(),
                    conditions: Vec::new(),
                };
                let outcome = parser.expr().and_then(|expr| {
                    parser.skip();
                    if parser.at < parser.chars.len() {
                        parser.fail("unexpected text after the definition")
                    } else {
                        Ok(expr)
                    }
                });
                for (condition, col) in &parser.conditions {
                    report.refuse(
                        Some(Location::new(
                            parser.file,
                            parser.line,
                            column(parser.base) + col - 1,
                            1,
                        )),
                        format!(
                            "`{}#{}` accepts a type `with {condition}`: OpenFGA conditions (CEL) are not translated",
                            parser.owner, parser.relation
                        ),
                        Some("an unconditional reading would allow more than the model does"),
                    );
                }
                match outcome {
                    Ok(expr) => {
                        let ty = types.last_mut().expect("a type is open");
                        if ty.relations.iter().any(|r| r.name == name) {
                            report.refuse(
                                Some(here(lead)),
                                format!("the relation `{name}` is declared twice in `{}`", ty.name),
                                None,
                            );
                        } else {
                            ty.relations.push(RelationDef {
                                name,
                                rewrite: expr.lower(),
                                at: Some(here(lead)),
                            });
                        }
                    }
                    Err((col, message)) => report.refuse(
                        Some(Location::new(file, line, col, 1)),
                        format!("`{name}`: {message}"),
                        None,
                    ),
                }
            }
            Some(other) => report.refuse(
                Some(here(lead)),
                format!("unexpected `{other}`"),
                Some("expected `model`, `schema`, `type`, `relations`, `define` or `condition`"),
            ),
            None => {}
        }
    }
    if !found_any && !report.failed() {
        report.refuse(
            Some(Location::new(file, 1, 1, 1)),
            "the model declares no type",
            Some("an OpenFGA model starts with `model`, `schema 1.1` and then `type` blocks"),
        );
    }
    (!report.failed()).then_some(types)
}

fn pick<'a>(value: &'a Json, names: &[&str]) -> Option<&'a Json> {
    names.iter().find_map(|name| value.get(name))
}

fn json_expr(value: &Json, path: &str, report: &mut Report, file: &str) -> Option<Rewrite> {
    let at = || Some(Location::new(file, 1, 1, 1));
    let object = value.as_object()?;
    let Some((kind, body)) = object.iter().next().filter(|_| object.len() == 1) else {
        report.refuse(at(), format!("{path}: a userset has exactly one operator"), None);
        return None;
    };
    let children = |body: &Json, report: &mut Report| -> Option<Vec<Rewrite>> {
        let list = pick(body, &["child"]).and_then(Json::as_array);
        let Some(list) = list else {
            report.refuse(at(), format!("{path}: `{kind}` has no `child` list"), None);
            return None;
        };
        let parts: Vec<Option<Rewrite>> = list.iter().map(|c| json_expr(c, path, report, file)).collect();
        parts.into_iter().collect()
    };
    match kind.as_str() {
        "this" => Some(Rewrite::This),
        "computedUserset" | "computed_userset" => {
            let relation = pick(body, &["relation"]).and_then(Json::as_str);
            if let Some(relation) = relation {
                Some(Rewrite::computed(relation))
            } else {
                report.refuse(at(), format!("{path}: `computedUserset` has no `relation`"), None);
                None
            }
        }
        "tupleToUserset" | "tuple_to_userset" => {
            let tupleset = pick(body, &["tupleset"])
                .and_then(|t| pick(t, &["relation"]))
                .and_then(Json::as_str);
            let computed = pick(body, &["computedUserset", "computed_userset"])
                .and_then(|t| pick(t, &["relation"]))
                .and_then(Json::as_str);
            if let (Some(tupleset), Some(computed)) = (tupleset, computed) {
                Some(Rewrite::from_parent(tupleset, computed))
            } else {
                report.refuse(
                    at(),
                    format!("{path}: `tupleToUserset` needs a `tupleset` and a `computedUserset` relation"),
                    None,
                );
                None
            }
        }
        "union" => children(body, report).map(Rewrite::union),
        "intersection" => children(body, report).map(Rewrite::intersection),
        "difference" => {
            let base = pick(body, &["base"]).and_then(|b| json_expr(b, path, report, file));
            let subtract = pick(body, &["subtract"]).and_then(|b| json_expr(b, path, report, file));
            match (base, subtract) {
                (Some(base), Some(subtract)) => Some(Rewrite::exclusion(base, subtract)),
                _ => None,
            }
        }
        other => {
            report.refuse(at(), format!("{path}: unknown operator `{other}`"), None);
            None
        }
    }
}

fn json_model(text: &str, options: &Options, report: &mut Report) -> Option<Vec<TypeDef>> {
    let file = options.model_file.as_str();
    let at = |line: u32, col: u32| Some(Location::new(file, line, col, 1));
    let document: Json = match serde_json::from_str(text) {
        Ok(found) => found,
        Err(err) => {
            report.refuse(
                at(
                    u32::try_from(err.line()).unwrap_or(1),
                    u32::try_from(err.column()).unwrap_or(1),
                ),
                format!("the model is not valid JSON: {err}"),
                None,
            );
            return None;
        }
    };
    if let Some(version) = pick(&document, &["schema_version", "schemaVersion"]).and_then(Json::as_str)
        && version != "1.1"
    {
        report.refuse(at(1, 1), "only the schema 1.1 is read", None);
    }
    let Some(definitions) = pick(&document, &["type_definitions", "typeDefinitions"]).and_then(Json::as_array) else {
        report.refuse(at(1, 1), "the model has no `type_definitions`", None);
        return None;
    };
    let mut types = Vec::new();
    for definition in definitions {
        let Some(name) = definition.get("type").and_then(Json::as_str) else {
            report.refuse(at(1, 1), "a type definition has no `type`", None);
            continue;
        };
        let metadata = definition.get("metadata").and_then(|m| m.get("relations"));
        let mut relations = Vec::new();
        if let Some(map) = definition.get("relations").and_then(Json::as_object) {
            for (relation, userset) in map {
                let path = format!("type `{name}`, relation `{relation}`");
                if let Some(entries) = metadata
                    .and_then(|m| m.get(relation))
                    .and_then(|m| pick(m, &["directly_related_user_types", "directlyRelatedUserTypes"]))
                    .and_then(Json::as_array)
                {
                    for entry in entries {
                        if let Some(condition) = entry.get("condition").and_then(Json::as_str) {
                            report.refuse(
                                at(1, 1),
                                format!(
                                    "{path}: accepts a type with the condition `{condition}`: OpenFGA conditions (CEL) are not translated"
                                ),
                                Some("an unconditional reading would allow more than the model does"),
                            );
                        }
                    }
                }
                if let Some(rewrite) = json_expr(userset, &path, report, file) {
                    relations.push(RelationDef {
                        name: relation.clone(),
                        rewrite,
                        at: at(1, 1),
                    });
                }
            }
        }
        types.push(TypeDef {
            name: name.to_string(),
            relations,
        });
    }
    (!report.failed()).then_some(types)
}

#[derive(Debug)]
struct RawTuple {
    user: String,
    relation: String,
    object: String,
    condition: bool,
    at: Location,
}

fn read_tuples(text: &str, options: &Options, defined: &BTreeSet<(String, String)>, report: &mut Report) -> Vec<Tuple> {
    let file = options.tuples_file.as_str();
    let raw = raw_tuples(text, file, report);
    let mut out: Vec<Tuple> = Vec::new();
    for item in raw {
        if item.condition {
            report.refuse(
                Some(item.at.clone()),
                format!(
                    "the tuple `{}#{}@{}` has a condition: OpenFGA conditions (CEL) are not translated",
                    item.object, item.relation, item.user
                ),
                Some("an unconditional reading would allow more than the tuple does"),
            );
            continue;
        }
        let Some(object) = object_ref(&item.object) else {
            report.refuse(
                Some(item.at.clone()),
                format!("`{}` is not an object (`type:id`)", item.object),
                None,
            );
            continue;
        };
        if !defined.contains(&(object.kind.clone(), item.relation.clone())) {
            report.refuse(
                Some(item.at.clone()),
                format!(
                    "the model has no relation `{}` on the type `{}`",
                    item.relation, object.kind
                ),
                None,
            );
            continue;
        }
        let subject = match item.user.split_once('#') {
            Some((set, relation)) => object_ref(set).map(|set| TupleSubject::Userset(set, relation.to_string())),
            None => object_ref(&item.user).map(TupleSubject::Object),
        };
        let Some(subject) = subject else {
            report.refuse(
                Some(item.at.clone()),
                format!(
                    "`{}` is not a user (`type:id`, `type:*` or `type:id#relation`)",
                    item.user
                ),
                None,
            );
            continue;
        };
        let tuple = Tuple {
            object,
            relation: item.relation,
            subject,
        };
        if out.contains(&tuple) {
            report.note(Some(item.at), format!("the tuple `{tuple}` is repeated; kept once"));
        } else {
            out.push(tuple);
        }
    }
    out
}

fn object_ref(text: &str) -> Option<ObjectRef> {
    let (kind, id) = text.split_once(':')?;
    (!kind.is_empty() && !id.is_empty()).then(|| ObjectRef::new(kind, id))
}

fn raw_tuples(text: &str, file: &str, report: &mut Report) -> Vec<RawTuple> {
    let at = |line: u32, col: u32| Location::new(file, line, col, 1);
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let value: Json = match serde_json::from_str(text) {
            Ok(found) => found,
            Err(err) => {
                report.refuse(
                    Some(at(
                        u32::try_from(err.line()).unwrap_or(1),
                        u32::try_from(err.column()).unwrap_or(1),
                    )),
                    format!("the tuples are not valid JSON: {err}"),
                    None,
                );
                return Vec::new();
            }
        };
        let list = value
            .as_array()
            .or_else(|| pick(&value, &["tuples", "tuple_keys", "tupleKeys"]).and_then(Json::as_array))
            .or_else(|| {
                value
                    .get("writes")
                    .and_then(|w| pick(w, &["tuple_keys", "tupleKeys"]))
                    .and_then(Json::as_array)
            });
        let Some(list) = list else {
            report.refuse(
                Some(at(1, 1)),
                "the tuples JSON is neither an array nor an object with `tuples`, `tuple_keys` or `writes.tuple_keys`",
                None,
            );
            return Vec::new();
        };
        let mut out = Vec::new();
        for (index, entry) in list.iter().enumerate() {
            let position = at(1, 1);
            let field = |name: &str| entry.get(name).and_then(Json::as_str).map(str::to_string);
            match (field("user"), field("relation"), field("object")) {
                (Some(user), Some(relation), Some(object)) => out.push(RawTuple {
                    user,
                    relation,
                    object,
                    condition: entry.get("condition").is_some_and(|c| !c.is_null()),
                    at: position,
                }),
                _ => report.refuse(
                    Some(position),
                    format!("tuple {} needs `user`, `relation` and `object`", index + 1),
                    None,
                ),
            }
        }
        return out;
    }
    if trimmed.starts_with("- ") || trimmed.starts_with("-\t") {
        return yaml_tuples(text, file, report);
    }
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .unwrap_or("");
    if first.contains('@') && first.contains('#') && !first.contains(',')
        || first.contains('@') && first.contains(':') && !first.contains(',')
    {
        return line_tuples(text, file, report);
    }
    csv_tuples(text, file, report)
}

fn line_tuples(text: &str, file: &str, report: &mut Report) -> Vec<RawTuple> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let body = raw.trim();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let at = Location::new(file, line, 1, 1);
        let parsed = body.split_once('#').and_then(|(object, rest)| {
            let (relation, user) = rest.split_once('@')?;
            Some((object.to_string(), relation.to_string(), user.to_string()))
        });
        match parsed {
            Some((object, relation, user)) => out.push(RawTuple {
                user,
                relation,
                object,
                condition: false,
                at,
            }),
            None => report.refuse(Some(at), "expected `object#relation@user`", None),
        }
    }
    out
}

fn yaml_tuples(text: &str, file: &str, report: &mut Report) -> Vec<RawTuple> {
    let mut out: Vec<RawTuple> = Vec::new();
    let mut current: Option<(u32, BTreeMap<String, String>)> = None;
    let mut flush = |current: &mut Option<(u32, BTreeMap<String, String>)>, report: &mut Report| {
        if let Some((line, map)) = current.take() {
            let at = Location::new(file, line, 1, 1);
            match (map.get("user"), map.get("relation"), map.get("object")) {
                (Some(user), Some(relation), Some(object)) => out.push(RawTuple {
                    user: user.clone(),
                    relation: relation.clone(),
                    object: object.clone(),
                    condition: map.contains_key("condition"),
                    at,
                }),
                _ => report.refuse(Some(at), "a tuple needs `user`, `relation` and `object`", None),
            }
        }
    };
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let body = raw.trim();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let (starts, body) = match body.strip_prefix('-') {
            Some(rest) => (true, rest.trim()),
            None => (false, body),
        };
        if starts {
            flush(&mut current, report);
            current = Some((line, BTreeMap::new()));
        }
        let Some((key, value)) = body.split_once(':') else {
            report.refuse(Some(Location::new(file, line, 1, 1)), "expected `key: value`", None);
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']).to_string();
        match current.as_mut() {
            Some((_, map)) => {
                map.insert(key.trim().to_string(), value);
            }
            None => report.refuse(Some(Location::new(file, line, 1, 1)), "a tuple starts with `-`", None),
        }
    }
    flush(&mut current, report);
    out
}

fn csv_tuples(text: &str, file: &str, report: &mut Report) -> Vec<RawTuple> {
    let records = match csv::parse(text) {
        Ok(found) => found,
        Err((line, col, message)) => {
            report.refuse(Some(Location::new(file, line, col, 1)), message, None);
            return Vec::new();
        }
    };
    let mut rows = records.into_iter();
    let Some(header) = rows.next() else {
        return Vec::new();
    };
    let names: Vec<String> = header.fields.iter().map(|f| f.text.to_ascii_lowercase()).collect();
    let index = |name: &str| names.iter().position(|n| n == name);
    let (Some(user_type), Some(user_id), Some(relation), Some(object_type), Some(object_id)) = (
        index("user_type"),
        index("user_id"),
        index("relation"),
        index("object_type"),
        index("object_id"),
    ) else {
        report.refuse(
            Some(Location::new(file, header.line, 1, 1)),
            "the CSV header must have `user_type`, `user_id`, `relation`, `object_type` and `object_id`",
            Some("the other accepted forms are JSON, a YAML list and `object#relation@user` lines"),
        );
        return Vec::new();
    };
    let user_relation = index("user_relation");
    let condition = index("condition_name");
    let mut out = Vec::new();
    for row in rows {
        let at = Location::new(file, row.line, 1, 1);
        let get = |i: usize| row.fields.get(i).map(|f| f.text.clone()).unwrap_or_default();
        let mut user = format!("{}:{}", get(user_type), get(user_id));
        if let Some(i) = user_relation.filter(|i| !get(*i).is_empty()) {
            user = format!("{user}#{}", get(i));
        }
        out.push(RawTuple {
            user,
            relation: get(relation),
            object: format!("{}:{}", get(object_type), get(object_id)),
            condition: condition.is_some_and(|i| !get(i).is_empty()),
            at,
        });
    }
    out
}
