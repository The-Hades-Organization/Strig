//! What every syntax builds into: the policy under construction, the positions of its elements,
//! the errors found so far and the extents that anchor the comments of the source.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::dsl::error::{Diagnostic, Location, Raw, Span};
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
            extents: Vec::new(),
            open: Vec::new(),
            invariants: BTreeMap::new(),
        }
    }

    pub fn location(&self, span: Span) -> Location {
        Location::new(Arc::clone(&self.file), span.line, span.col, span.len.max(1))
    }

    pub fn report(&mut self, raw: Raw) {
        self.diagnostics.push(raw.locate(&self.file));
    }

    /// An error that has a second side: where the clashing declaration lives.
    pub fn conflict(&mut self, raw: Raw, first: Option<Location>) {
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
        for extent in &mut self.extents {
            if extent.id == from {
                extent.id = to.to_string();
            } else if let Some(rest) = extent.id.strip_prefix(&below) {
                extent.id = format!("{to}/{rest}");
            }
        }
        self.origins.rename_prefix(from, to);
    }

    /// Ends the innermost open element at the last token consumed.
    pub fn close(&mut self, last: Span) {
        if let Some(at) = self.open.pop() {
            if let Some(extent) = self.extents.get_mut(at) {
                extent.last = extent.last.max(last.line);
            }
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
        let mut diagnostics = self.diagnostics;
        diagnostics.sort_by_key(|d| d.location.as_ref().map(|at| (at.line, at.column)));
        (self.policy, self.origins, diagnostics)
    }

    fn anchor_notes(&self, comments: &[Comment]) -> Vec<Note> {
        let mut notes = Vec::new();
        let mut at = 0;
        while let Some(comment) = comments.get(at) {
            if !comment.own_line {
                at += 1;
                let anchor = self
                    .inline_anchor(comment.span.line)
                    .or_else(|| self.own_line_anchor(comment.span.line, comment.span.line));
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
            let anchor = self.own_line_anchor(first, last);
            for comment in &comments[start..=end] {
                notes.extend(anchor.clone().map(|a| self.note(comment, a)));
            }
            at = end + 1;
        }
        notes
    }

    fn note(&self, comment: &Comment, anchor: NoteAnchor) -> Note {
        Note {
            text: comment.text.clone(),
            anchor,
            origin: NoteOrigin {
                file: self.file.to_string(),
                language: self.language,
                line: comment.span.line,
                column: comment.span.col,
            },
        }
    }

    /// A comment after code: it belongs to the deepest element that starts on its line, or else
    /// (`} // text`) to the one that ends there.
    fn inline_anchor(&self, line: u32) -> Option<NoteAnchor> {
        let deepest = |matches: &dyn Fn(&Extent) -> bool| {
            self.extents
                .iter()
                .filter(|e| matches(e))
                .max_by_key(|e| (e.depth, std::cmp::Reverse(e.first)))
        };
        if let Some(extent) = deepest(&|e| e.first == line) {
            return Some(anchor(&extent.id, Placement::Inline));
        }
        deepest(&|e| e.last == line).map(|e| anchor(&e.id, Placement::After))
    }

    /// Comments on their own lines `first..=last`: they stay with the element they touch.
    fn own_line_anchor(&self, first: u32, last: u32) -> Option<NoteAnchor> {
        let container = self
            .extents
            .iter()
            .enumerate()
            .filter(|(_, e)| e.first < first && e.last > last)
            .max_by_key(|(_, e)| e.depth)
            .map(|(i, _)| i);
        let siblings = || self.extents.iter().filter(move |e| e.parent == container);
        let previous = siblings().filter(|e| e.last < first).max_by_key(|e| e.last);
        let next = siblings().filter(|e| e.first > last).min_by_key(|e| e.first);
        let glued_above = previous.is_some_and(|p| p.last + 1 == first);
        let blank_below = next.is_none_or(|n| n.first != last + 1);
        match (previous, next) {
            (Some(p), _) if glued_above && blank_below => Some(anchor(&p.id, Placement::After)),
            (_, Some(n)) => Some(anchor(&n.id, Placement::Before)),
            (Some(p), None) => Some(anchor(&p.id, Placement::After)),
            (None, None) => container
                .and_then(|c| self.extents.get(c))
                .map(|c| anchor(&c.id, Placement::Before)),
        }
    }
}

fn anchor(element: &str, placement: Placement) -> NoteAnchor {
    NoteAnchor {
        element: element.to_string(),
        placement,
    }
}
