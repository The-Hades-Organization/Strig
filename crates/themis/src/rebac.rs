use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::resource::ObjectRef;

/// Id curinga: a tupla `document:42#viewer@user:*` vale para todo sujeito do tipo `user`.
pub const WILDCARD: &str = "*";

/// Quem está do lado direito de uma tupla.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TupleSubject {
    /// Um objeto direto (`user:alice`, `user:*`).
    Object(ObjectRef),
    /// Todos que têm `relation` sobre `object` (`group:9#member`).
    Userset(ObjectRef, String),
}

impl fmt::Display for TupleSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TupleSubject::Object(object) => write!(f, "{object}"),
            TupleSubject::Userset(object, relation) => write!(f, "{object}#{relation}"),
        }
    }
}

/// Fato de relação: `object#relation@subject`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tuple {
    pub object: ObjectRef,
    pub relation: String,
    pub subject: TupleSubject,
}

impl fmt::Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}@{}", self.object, self.relation, self.subject)
    }
}

impl Tuple {
    pub fn new(object: ObjectRef, relation: impl Into<String>, subject: ObjectRef) -> Self {
        Self {
            object,
            relation: relation.into(),
            subject: TupleSubject::Object(subject),
        }
    }

    pub fn userset(
        object: ObjectRef,
        relation: impl Into<String>,
        set: ObjectRef,
        set_relation: impl Into<String>,
    ) -> Self {
        Self {
            object,
            relation: relation.into(),
            subject: TupleSubject::Userset(set, set_relation.into()),
        }
    }
}

/// Armazenamento das tuplas. Uma implementação em banco consulta por `(object, relation)`.
pub trait TupleStore {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject));
}

impl<T: TupleStore + ?Sized> TupleStore for &T {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject)) {
        (**self).visit(object, relation, visitor);
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTuples {
    map: HashMap<(ObjectRef, String), Vec<TupleSubject>>,
}

impl InMemoryTuples {
    pub fn new() -> Self {
        Self::default()
    }

    /// Devolve `false` se a tupla já existia.
    pub fn insert(&mut self, tuple: Tuple) -> bool {
        let entry = self.map.entry((tuple.object, tuple.relation)).or_default();
        if entry.contains(&tuple.subject) {
            return false;
        }
        entry.push(tuple.subject);
        true
    }

    pub fn remove(&mut self, tuple: &Tuple) -> bool {
        let key = (tuple.object.clone(), tuple.relation.clone());
        let Some(entry) = self.map.get_mut(&key) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|s| s != &tuple.subject);
        before != entry.len()
    }

    pub fn len(&self) -> usize {
        self.map.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FromIterator<Tuple> for InMemoryTuples {
    fn from_iter<I: IntoIterator<Item = Tuple>>(iter: I) -> Self {
        let mut store = Self::new();
        for tuple in iter {
            store.insert(tuple);
        }
        store
    }
}

impl TupleStore for InMemoryTuples {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject)) {
        if let Some(subjects) = self.map.get(&(object.clone(), relation.to_string())) {
            for subject in subjects {
                visitor(subject);
            }
        }
    }
}

/// Como uma relação se deriva de outras (userset rewrite do Zanzibar).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "rewrite", rename_all = "snake_case")]
pub enum Rewrite {
    /// Só as tuplas gravadas para a própria relação.
    This,
    /// Outra relação do mesmo objeto (`editor` implica `viewer`).
    Computed {
        relation: String,
    },
    /// Segue `tupleset` até o objeto pai e checa `computed` lá (`parent->member`).
    TupleToUserset {
        tupleset: String,
        computed: String,
    },
    Union {
        of: Vec<Rewrite>,
    },
    Intersection {
        of: Vec<Rewrite>,
    },
    Exclusion {
        base: Box<Rewrite>,
        subtract: Box<Rewrite>,
    },
}

impl Rewrite {
    pub fn computed(relation: impl Into<String>) -> Self {
        Self::Computed {
            relation: relation.into(),
        }
    }

    pub fn from_parent(tupleset: impl Into<String>, computed: impl Into<String>) -> Self {
        Self::TupleToUserset {
            tupleset: tupleset.into(),
            computed: computed.into(),
        }
    }

    pub fn union(of: impl IntoIterator<Item = Rewrite>) -> Self {
        Self::Union {
            of: of.into_iter().collect(),
        }
    }

    pub fn intersection(of: impl IntoIterator<Item = Rewrite>) -> Self {
        Self::Intersection {
            of: of.into_iter().collect(),
        }
    }

    pub fn exclusion(base: Rewrite, subtract: Rewrite) -> Self {
        Self::Exclusion {
            base: Box::new(base),
            subtract: Box::new(subtract),
        }
    }
}

static THIS: Rewrite = Rewrite::This;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RebacError {
    #[error("profundidade máxima de relação ({0}) excedida")]
    DepthExceeded(usize),
}

/// Regras de derivação por `(tipo de objeto, relação)`. Relação sem regra vale [`Rewrite::This`].
#[derive(Debug, Clone, Default)]
pub struct RelationSchema {
    rules: HashMap<(String, String), Rewrite>,
}

impl RelationSchema {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn relation(mut self, kind: impl Into<String>, relation: impl Into<String>, rewrite: Rewrite) -> Self {
        self.rules.insert((kind.into(), relation.into()), rewrite);
        self
    }

    pub fn rewrite(&self, kind: &str, relation: &str) -> &Rewrite {
        self.rules
            .get(&(kind.to_string(), relation.to_string()))
            .unwrap_or(&THIS)
    }

    /// `subject` tem `relation` sobre `object`?
    pub fn check(
        &self,
        store: &dyn TupleStore,
        object: &ObjectRef,
        relation: &str,
        subject: &ObjectRef,
        max_depth: usize,
    ) -> Result<bool, RebacError> {
        Checker {
            schema: self,
            store,
            subject,
            max_depth,
            visiting: HashSet::new(),
        }
        .relation(object, relation, 0)
    }
}

struct Checker<'a> {
    schema: &'a RelationSchema,
    store: &'a dyn TupleStore,
    subject: &'a ObjectRef,
    max_depth: usize,
    visiting: HashSet<(ObjectRef, String)>,
}

impl<'a> Checker<'a> {
    fn relation(&mut self, object: &ObjectRef, relation: &str, depth: usize) -> Result<bool, RebacError> {
        if depth > self.max_depth {
            return Err(RebacError::DepthExceeded(self.max_depth));
        }
        let key = (object.clone(), relation.to_string());
        if !self.visiting.insert(key.clone()) {
            return Ok(false);
        }
        let schema = self.schema;
        let result = self.eval(schema.rewrite(&object.kind, relation), object, relation, depth);
        self.visiting.remove(&key);
        result
    }

    fn eval(
        &mut self,
        rewrite: &'a Rewrite,
        object: &ObjectRef,
        relation: &str,
        depth: usize,
    ) -> Result<bool, RebacError> {
        match rewrite {
            Rewrite::This => self.direct(object, relation, depth),
            Rewrite::Computed { relation: other } => self.relation(object, other, depth + 1),
            Rewrite::TupleToUserset { tupleset, computed } => {
                for parent in self.subjects(object, tupleset) {
                    let parent = match parent {
                        TupleSubject::Object(o) | TupleSubject::Userset(o, _) => o,
                    };
                    if self.relation(&parent, computed, depth + 1)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rewrite::Union { of } => {
                for rw in of {
                    if self.eval(rw, object, relation, depth)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rewrite::Intersection { of } => {
                if of.is_empty() {
                    return Ok(false);
                }
                for rw in of {
                    if !self.eval(rw, object, relation, depth)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Rewrite::Exclusion { base, subtract } => {
                Ok(self.eval(base, object, relation, depth)? && !self.eval(subtract, object, relation, depth)?)
            }
        }
    }

    fn direct(&mut self, object: &ObjectRef, relation: &str, depth: usize) -> Result<bool, RebacError> {
        for subject in self.subjects(object, relation) {
            match subject {
                TupleSubject::Object(o) => {
                    let wildcard = o.id == WILDCARD && o.kind == self.subject.kind && self.subject.id != WILDCARD;
                    if o == *self.subject || wildcard {
                        return Ok(true);
                    }
                }
                TupleSubject::Userset(set, set_relation) => {
                    if self.relation(&set, &set_relation, depth + 1)? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn subjects(&self, object: &ObjectRef, relation: &str) -> Vec<TupleSubject> {
        let mut out = Vec::new();
        self.store.visit(object, relation, &mut |s| out.push(s.clone()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(kind: &str, id: &str) -> ObjectRef {
        ObjectRef::new(kind, id)
    }

    fn schema() -> RelationSchema {
        RelationSchema::new()
            .relation(
                "document",
                "editor",
                Rewrite::union([Rewrite::This, Rewrite::computed("owner")]),
            )
            .relation(
                "document",
                "viewer",
                Rewrite::union([
                    Rewrite::This,
                    Rewrite::computed("editor"),
                    Rewrite::from_parent("parent", "member"),
                ]),
            )
            .relation(
                "document",
                "commenter",
                Rewrite::exclusion(Rewrite::computed("viewer"), Rewrite::computed("banned")),
            )
    }

    fn store() -> InMemoryTuples {
        [
            Tuple::new(o("document", "d1"), "owner", o("user", "alice")),
            Tuple::new(o("document", "d1"), "parent", o("folder", "f1")),
            Tuple::new(o("folder", "f1"), "member", o("user", "bob")),
            Tuple::userset(o("folder", "f1"), "member", o("group", "g1"), "member"),
            Tuple::new(o("group", "g1"), "member", o("user", "carol")),
            Tuple::new(o("document", "d1"), "banned", o("user", "bob")),
            Tuple::new(o("document", "pub"), "viewer", o("user", WILDCARD)),
        ]
        .into_iter()
        .collect()
    }

    fn check(object: ObjectRef, relation: &str, subject: ObjectRef) -> bool {
        schema().check(&store(), &object, relation, &subject, 16).unwrap()
    }

    #[test]
    fn computed_and_parent_relations() {
        assert!(check(o("document", "d1"), "viewer", o("user", "alice")));
        assert!(check(o("document", "d1"), "viewer", o("user", "bob")));
        assert!(check(o("document", "d1"), "viewer", o("user", "carol")));
        assert!(!check(o("document", "d1"), "editor", o("user", "bob")));
        assert!(!check(o("document", "d1"), "viewer", o("user", "dave")));
    }

    #[test]
    fn exclusion_removes_banned() {
        assert!(check(o("document", "d1"), "commenter", o("user", "carol")));
        assert!(!check(o("document", "d1"), "commenter", o("user", "bob")));
    }

    #[test]
    fn wildcard_matches_any_subject_of_kind() {
        assert!(check(o("document", "pub"), "viewer", o("user", "zed")));
        assert!(!check(o("document", "pub"), "viewer", o("service", "zed")));
    }

    #[test]
    fn tuple_display() {
        let t = Tuple::userset(o("folder", "f1"), "member", o("group", "g1"), "member");
        assert_eq!(t.to_string(), "folder:f1#member@group:g1#member");
    }

    #[test]
    fn cycle_terminates_and_depth_is_bounded() {
        let schema = RelationSchema::new().relation("a", "r", Rewrite::from_parent("next", "r"));
        let store: InMemoryTuples = (0..50)
            .map(|i| Tuple::new(o("a", &i.to_string()), "next", o("a", &(i + 1).to_string())))
            .chain([Tuple::new(o("a", "x"), "next", o("a", "x"))])
            .collect();
        assert!(!schema.check(&store, &o("a", "x"), "r", &o("user", "u"), 16).unwrap());
        assert_eq!(
            schema.check(&store, &o("a", "0"), "r", &o("user", "u"), 16),
            Err(RebacError::DepthExceeded(16))
        );
    }
}
