use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::resource::ObjectRef;

/// Wildcard id: the tuple `document:42#viewer@user:*` holds for every subject of kind `user`.
pub const WILDCARD: &str = "*";

/// Who is on the right-hand side of a tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TupleSubject {
    /// A direct object (`user:alice`, `user:*`).
    Object(ObjectRef),
    /// Everyone who has `relation` on `object` (`group:9#member`).
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

/// Relation fact: `object#relation@subject`.
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

/// Storage of the tuples. A database implementation queries by `(object, relation)`.
pub trait TupleStore {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject));
}

impl<T: TupleStore + ?Sized> TupleStore for &T {
    fn visit(&self, object: &ObjectRef, relation: &str, visitor: &mut dyn FnMut(&TupleSubject)) {
        (**self).visit(object, relation, visitor);
    }
}

/// A [`TupleStore`] that can also be walked from the other side: every object of a kind, and every
/// subject of an object. The reverse queries of [`RelationSchema`] (which objects a subject
/// reaches, who reaches an object) are built on these two methods; a database implementation
/// answers each with one indexed query.
pub trait TupleIndex: TupleStore {
    /// Objects of `kind` that appear as the object of at least one tuple. May repeat an object.
    ///
    /// Every derivation of a relation bottoms out in a tuple written on the object itself, so an
    /// object missing here has no relation at all.
    fn visit_objects(&self, kind: &str, visitor: &mut dyn FnMut(&ObjectRef));

    /// Every `(relation, subject)` written on `object`.
    fn visit_subjects(&self, object: &ObjectRef, visitor: &mut dyn FnMut(&str, &TupleSubject));
}

impl<T: TupleIndex + ?Sized> TupleIndex for &T {
    fn visit_objects(&self, kind: &str, visitor: &mut dyn FnMut(&ObjectRef)) {
        (**self).visit_objects(kind, visitor);
    }

    fn visit_subjects(&self, object: &ObjectRef, visitor: &mut dyn FnMut(&str, &TupleSubject)) {
        (**self).visit_subjects(object, visitor);
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

    /// Returns `false` if the tuple already existed.
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

impl TupleIndex for InMemoryTuples {
    fn visit_objects(&self, kind: &str, visitor: &mut dyn FnMut(&ObjectRef)) {
        for (object, _) in self.map.keys().filter(|(object, _)| object.kind == kind) {
            visitor(object);
        }
    }

    fn visit_subjects(&self, object: &ObjectRef, visitor: &mut dyn FnMut(&str, &TupleSubject)) {
        for ((o, relation), subjects) in &self.map {
            if o == object {
                subjects.iter().for_each(|s| visitor(relation, s));
            }
        }
    }
}

/// How a relation is derived from others (Zanzibar's userset rewrite).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "rewrite", rename_all = "snake_case")]
pub enum Rewrite {
    /// Only the tuples written for the relation itself.
    This,
    /// Another relation on the same object (`editor` implies `viewer`).
    Computed {
        relation: String,
    },
    /// Follows `tupleset` to the parent object and checks `computed` there (`parent->member`).
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

/// Derivation rules by `(object kind, relation)`. A relation with no rule is [`Rewrite::This`].
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

    /// Does `subject` have `relation` on `object`?
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

    /// Objects of `kind` on which `subject` has `relation`, usersets and rewrites included.
    ///
    /// Candidates come from [`TupleIndex::visit_objects`] and each one goes through
    /// [`RelationSchema::check`], so the answer is exactly what `check` would say object by object.
    /// A candidate whose derivation exceeds `max_depth` is reported in the second list instead of
    /// being silently dropped.
    pub fn objects_with(
        &self,
        index: &dyn TupleIndex,
        kind: &str,
        relation: &str,
        subject: &ObjectRef,
        max_depth: usize,
    ) -> (BTreeSet<ObjectRef>, BTreeSet<ObjectRef>) {
        let mut candidates = BTreeSet::new();
        index.visit_objects(kind, &mut |o| {
            candidates.insert(o.clone());
        });
        let mut holds = BTreeSet::new();
        let mut failed = BTreeSet::new();
        for object in candidates {
            match self.check(index, &object, relation, subject, max_depth) {
                Ok(true) => {
                    holds.insert(object);
                }
                Ok(false) => {}
                Err(_) => {
                    failed.insert(object);
                }
            }
        }
        (holds, failed)
    }

    /// Subjects that may hold `relation` on `object`: the direct subjects of the relation, the ones
    /// of the relations it is computed from and the ones of the parents it follows. Usersets stay
    /// as usersets (`group:9#member` is reported as such, not expanded into its members).
    ///
    /// This is a superset when the relation uses an exclusion or an intersection: confirm a given
    /// subject with [`RelationSchema::check`].
    ///
    /// # Errors
    ///
    /// [`RebacError::DepthExceeded`] when the derivation is deeper than `max_depth`.
    pub fn subjects_of(
        &self,
        index: &dyn TupleIndex,
        object: &ObjectRef,
        relation: &str,
        max_depth: usize,
    ) -> Result<Vec<TupleSubject>, RebacError> {
        let mut out = Vec::new();
        let mut visiting = HashSet::new();
        self.collect_subjects(index, object, relation, 0, max_depth, &mut visiting, &mut out)?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_subjects(
        &self,
        index: &dyn TupleIndex,
        object: &ObjectRef,
        relation: &str,
        depth: usize,
        max_depth: usize,
        visiting: &mut HashSet<(ObjectRef, String)>,
        out: &mut Vec<TupleSubject>,
    ) -> Result<(), RebacError> {
        if depth > max_depth {
            return Err(RebacError::DepthExceeded(max_depth));
        }
        let key = (object.clone(), relation.to_string());
        if !visiting.insert(key.clone()) {
            return Ok(());
        }
        let result = self.collect_rewrite(
            index,
            self.rewrite(&object.kind, relation),
            object,
            relation,
            depth,
            max_depth,
            visiting,
            out,
        );
        visiting.remove(&key);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_rewrite(
        &self,
        index: &dyn TupleIndex,
        rewrite: &Rewrite,
        object: &ObjectRef,
        relation: &str,
        depth: usize,
        max_depth: usize,
        visiting: &mut HashSet<(ObjectRef, String)>,
        out: &mut Vec<TupleSubject>,
    ) -> Result<(), RebacError> {
        match rewrite {
            Rewrite::This => {
                index.visit(object, relation, &mut |s| {
                    if !out.contains(s) {
                        out.push(s.clone());
                    }
                });
                Ok(())
            }
            Rewrite::Computed { relation: other } => {
                self.collect_subjects(index, object, other, depth + 1, max_depth, visiting, out)
            }
            Rewrite::TupleToUserset { tupleset, computed } => {
                let mut parents = Vec::new();
                index.visit(object, tupleset, &mut |s| parents.push(s.clone()));
                for parent in parents {
                    let (TupleSubject::Object(p) | TupleSubject::Userset(p, _)) = parent;
                    self.collect_subjects(index, &p, computed, depth + 1, max_depth, visiting, out)?;
                }
                Ok(())
            }
            Rewrite::Union { of } | Rewrite::Intersection { of } => {
                for rw in of {
                    self.collect_rewrite(index, rw, object, relation, depth, max_depth, visiting, out)?;
                }
                Ok(())
            }
            Rewrite::Exclusion { base, .. } => {
                self.collect_rewrite(index, base, object, relation, depth, max_depth, visiting, out)
            }
        }
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
