//! What every syntax builds into: the policy under construction, the positions of its elements,
//! the errors found so far and the extents that anchor the comments of the source.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::dsl::error::{Diagnostic, Location, MAX_DIAGNOSTICS, Raw, Span, capped};
use crate::dsl::lex::Comment;
use crate::dsl::policy::{Language, Note, NoteAnchor, NoteOrigin, Origins, Placement, Policy, ids};

/// The lines an element of the source covers, and where it sits in the nesting.
#[derive(Debug, Clone)]
struct Extent {
    id: String,
    first: u32,
    last: u32,
    parent: Option<usize>,
    depth: usize,
}

pub(crate) struct Builder {
    file: Arc<str>,
    language: Language,
    pub policy: Policy,
    pub origins: Origins,
    diagnostics: Vec<Diagnostic>,
    hidden: usize,
    extents: Vec<Extent>,
    open: Vec<usize>,
    invariants: BTreeMap<String, usize>,
}

impl Builder {
    pub fn new(file: Arc<str>, language: Language) -> Self {
        Self {
            file,
            language,
            policy: Policy::default(),
            origins: Origins::default(),
            diagnostics: Vec::new(),
            hidden: 0,
            extents: Vec::new(),
            open: Vec::new(),
            invariants: BTreeMap::new(),
        }
    }

    pub fn location(&self, span: Span) -> Location {
        Location::new(Arc::clone(&self.file), span.line, span.col, span.len.max(1))
    }

    pub fn report(&mut self, raw: Raw) {
        if self.diagnostics.len() >= MAX_DIAGNOSTICS {
            self.hidden += 1;
            return;
        }
        self.diagnostics.push(raw.locate(&self.file));
    }

    /// An error that has a second side: where the clashing declaration lives.
    pub fn conflict(&mut self, raw: Raw, first: Option<Location>) {
        if self.diagnostics.len() >= MAX_DIAGNOSTICS {
            self.hidden += 1;
            return;
        }
        let mut diagnostic = raw.locate(&self.file);
        diagnostic.related = first;
        self.diagnostics.push(diagnostic);
    }

    /// Where an element was first declared, if it was.
    pub fn declared(&self, id: &str) -> Option<Location> {
        self.origins.exact(id).cloned()
    }

    pub fn mark(&mut self, id: &str, span: Span) {
        let at = self.location(span);
        self.origins.insert(id.to_string(), at);
    }

    /// Starts an element that spans lines: its comments hang on it.
    pub fn open(&mut self, id: &str, span: Span) {
        self.mark(id, span);
        let at = self.extents.len();
        self.extents.push(Extent {
            id: id.to_string(),
            first: span.line,
            last: span.line,
            parent: self.open.last().copied(),
            depth: self.open.len(),
        });
        self.open.push(at);
    }

    /// Renames an element (and what hangs under it) once its name is known: an override is named
    /// by a field of its own body.
    pub fn rename(&mut self, from: &str, to: &str) {
        let below = format!("{from}/");
        // The element was the last one opened, so it and what hangs under it end the vector.
        for extent in self.extents.iter_mut().rev() {
            if extent.id == from {
                extent.id = to.to_string();
            } else if let Some(rest) = extent.id.strip_prefix(&below) {
                extent.id = format!("{to}/{rest}");
            } else {
                break;
            }
        }
        self.origins.rename_prefix(from, to);
    }

    /// Ends the innermost open element at the last token consumed.
    pub fn close(&mut self, last: Span) {
        if let Some(at) = self.open.pop()
            && let Some(extent) = self.extents.get_mut(at)
        {
            extent.last = extent.last.max(last.line);
        }
    }

    /// The id of the next invariant of this kind: invariants are numbered per kind, from 1.
    pub fn next_invariant(&mut self, kind: &str) -> String {
        let count = self.invariants.entry(kind.to_string()).or_insert(0);
        *count += 1;
        ids::invariant(kind, *count)
    }

    /// Hands out the result: the diagnostics sorted by position, and the comments anchored.
    pub fn finish(mut self, comments: &[Comment]) -> (Policy, Origins, Vec<Diagnostic>) {
        self.policy.notes = self.anchor_notes(comments);
        // Stable: the comments of one anchor keep the order they were written in, and the order
        // of the anchors no longer depends on how the syntax lays the elements out.
        self.policy.notes.sort_by(|a, b| a.anchor.cmp(&b.anchor));
        let mut diagnostics = self.diagnostics;
        diagnostics.sort_by_key(|d| d.location.as_ref().map(|at| (at.line, at.column)));
        (self.policy, self.origins, capped(diagnostics, self.hidden))
    }

    fn anchor_notes(&self, comments: &[Comment]) -> Vec<Note> {
        let index = Index::new(&self.extents);
        let mut notes = Vec::new();
        let mut at = 0;
        while let Some(comment) = comments.get(at) {
            if !comment.own_line {
                at += 1;
                let anchor = index
                    .inline_anchor(&self.extents, comment.span.line)
                    .or_else(|| index.own_line_anchor(&self.extents, comment.span.line, comment.span.line));
                notes.extend(anchor.map(|a| self.note(comment, a)));
                continue;
            }
            // A run of comment lines with no gap is anchored together.
            let start = at;
            let mut end = at;
            while comments
                .get(end + 1)
                .is_some_and(|next| next.own_line && next.span.line == comments[end].span.line + 1)
            {
                end += 1;
            }
            let first = comments[start].span.line;
            let last = comments[end].span.line;
            let anchor = index.own_line_anchor(&self.extents, first, last);
            for comment in &comments[start..=end] {
                notes.extend(anchor.clone().map(|a| self.note(comment, a)));
            }
            at = end + 1;
        }
        notes
    }

    fn note(&self, comment: &Comment, (anchor, field): (NoteAnchor, Option<String>)) -> Note {
        Note {
            text: comment.text.clone(),
            anchor,
            origin: NoteOrigin {
                file: self.file.to_string(),
                language: self.language,
                line: comment.span.line,
                column: comment.span.col,
                field,
            },
        }
    }
}

/// Where a comment is anchored: the element and its side, and the field of the element it was
/// written next to, kept as a hint for the printer.
type Anchored = (NoteAnchor, Option<String>);

/// The extents looked up by line: building it is linear and each question costs a binary search, so
/// anchoring the comments of a source takes n·log n however many there are.
struct Index {
    /// The extents that start on a line, in order of appearance.
    starting: HashMap<u32, Vec<usize>>,
    /// The extents that end on a line, in order of appearance.
    ending: HashMap<u32, Vec<usize>>,
    /// The children of each extent, in source order; the extra last entry holds the roots.
    children: Vec<Vec<usize>>,
}

impl Index {
    fn new(extents: &[Extent]) -> Self {
        let mut starting: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut ending: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut children = vec![Vec::new(); extents.len() + 1];
        for (at, extent) in extents.iter().enumerate() {
            starting.entry(extent.first).or_default().push(at);
            ending.entry(extent.last).or_default().push(at);
            children[extent.parent.unwrap_or(extents.len())].push(at);
        }
        Self {
            starting,
            ending,
            children,
        }
    }

    /// A comment after code: it belongs to the deepest element that starts on its line, or else
    /// (`} // text`) to the one that ends there.
    fn inline_anchor(&self, extents: &[Extent], line: u32) -> Option<Anchored> {
        let deepest = |found: Option<&Vec<usize>>| {
            found?
                .iter()
                .map(|at| &extents[*at])
                .max_by_key(|e| (e.depth, std::cmp::Reverse(e.first)))
        };
        if let Some(extent) = deepest(self.starting.get(&line)) {
            return Some(anchor(&extent.id, Placement::Inline));
        }
        deepest(self.ending.get(&line)).map(|e| anchor(&e.id, Placement::After))
    }

    /// The deepest extent that holds the lines `first..=last` strictly inside it.
    fn container(&self, extents: &[Extent], first: u32, last: u32) -> Option<usize> {
        let mut found = None;
        let mut level = &self.children[extents.len()];
        loop {
            let below = level.partition_point(|at| extents[*at].first < first);
            let Some(candidate) = below.checked_sub(1).map(|i| level[i]) else {
                return found;
            };
            if extents[candidate].last <= last {
                return found;
            }
            found = Some(candidate);
            level = &self.children[candidate];
        }
    }

    /// Comments on their own lines `first..=last`: they stay with the element they touch.
    fn own_line_anchor(&self, extents: &[Extent], first: u32, last: u32) -> Option<Anchored> {
        let container = self.container(extents, first, last);
        let siblings = &self.children[container.unwrap_or(extents.len())];
        let before = siblings.partition_point(|at| extents[*at].last < first);
        let previous = before.checked_sub(1).map(|i| &extents[siblings[i]]);
        let after = siblings.partition_point(|at| extents[*at].first <= last);
        let next = siblings.get(after).map(|at| &extents[*at]);
        let glued_above = previous.is_some_and(|p| p.last + 1 == first);
        let blank_below = next.is_none_or(|n| n.first != last + 1);
        match (previous, next) {
            (Some(p), _) if glued_above && blank_below => Some(anchor(&p.id, Placement::After)),
            (_, Some(n)) => Some(anchor(&n.id, Placement::Before)),
            (Some(p), None) => Some(anchor(&p.id, Placement::After)),
            (None, None) => container
                .and_then(|c| extents.get(c))
                .map(|c| anchor(&c.id, Placement::Before)),
        }
    }
}

/// The anchor of an extent: its element, with no field in it, so every syntax anchors alike. The
/// field the comment sits next to goes along as a hint.
fn anchor(extent_id: &str, placement: Placement) -> Anchored {
    let (element, field) = ids::split(extent_id);
    (
        NoteAnchor {
            element: element.to_string(),
            placement,
        },
        field.map(str::to_string),
    )
}
