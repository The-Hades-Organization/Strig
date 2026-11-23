//! Validity windows for grants and role assignments.
//!
//! A window is a half-open interval of milliseconds since the Unix epoch: `valid_from` is
//! inclusive and `valid_until` is exclusive. Either end may be absent. The crate never reads a
//! clock; the caller passes the instant with [`crate::Context::at`].
//!
//! Outside its window a grant or a role assignment does not exist for the decision, the
//! explanation and the capabilities. Without an instant in the context the rule fails closed: an
//! `allow` (or a role assignment used by an `allow`) with a window is ignored, and a `deny` with a
//! window still holds.
//!
//! The ABAC environment is a separate input. A condition that reads `env.now` sees whatever the
//! caller put in [`crate::Context::env`]; windows read only [`crate::Context::at`]. Feed both from
//! the same value so a condition and a window never disagree about the current time.

use crate::grant::Grant;
use crate::subject::RoleAssignment;

/// A window whose end is not after its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidityError {
    #[error("empty validity window: valid_until {until} is not after valid_from {from}")]
    Inverted { from: u64, until: u64 },
}

/// Optional start (inclusive) and end (exclusive) of a validity window, in milliseconds since the
/// Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Validity {
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
}

impl Validity {
    /// No bounds: always in force.
    pub const ALWAYS: Validity = Validity {
        valid_from: None,
        valid_until: None,
    };

    /// Window `[from, until)`.
    ///
    /// # Errors
    /// [`ValidityError::Inverted`] when `until` is not after `from`.
    pub fn between(from: u64, until: u64) -> Result<Self, ValidityError> {
        let window = Self {
            valid_from: Some(from),
            valid_until: Some(until),
        };
        window.check().map(|()| window)
    }

    /// # Errors
    /// [`ValidityError::Inverted`] when both ends are set and `valid_until <= valid_from`.
    pub fn check(&self) -> Result<(), ValidityError> {
        match (self.valid_from, self.valid_until) {
            (Some(from), Some(until)) if until <= from => Err(ValidityError::Inverted { from, until }),
            _ => Ok(()),
        }
    }

    pub fn is_unbounded(&self) -> bool {
        self.valid_from.is_none() && self.valid_until.is_none()
    }

    /// Is `now` inside the window? `valid_from` is inclusive, `valid_until` exclusive.
    pub fn contains(&self, now: u64) -> bool {
        self.valid_from.is_none_or(|from| now >= from) && self.valid_until.is_none_or(|until| now < until)
    }

    /// Is the item in force at `now`? Without an instant, only an unbounded item is, unless
    /// `holds_without_now` says the item must keep holding (a `deny`: an error never opens access).
    pub(crate) fn in_force(&self, now: Option<u64>, holds_without_now: bool) -> bool {
        match now {
            Some(now) => self.contains(now),
            None => holds_without_now || self.is_unbounded(),
        }
    }

    /// Has the window closed for good at `now`? True when `valid_until` is not after `now`. Without an
    /// instant nothing is known to have ended. Not the same as "not in force": an item that starts
    /// later is not in force yet but will be, so a rule that guards against handing out access must
    /// still count it.
    pub(crate) fn has_ended(&self, now: Option<u64>) -> bool {
        matches!((now, self.valid_until), (Some(now), Some(until)) if until <= now)
    }

    /// The next start or end strictly after `now`, if any.
    pub fn next_boundary(&self, now: u64) -> Option<u64> {
        [self.valid_from, self.valid_until]
            .into_iter()
            .flatten()
            .filter(|boundary| *boundary > now)
            .min()
    }
}

/// The next instant after `now` at which one of the grants or role assignments starts or stops
/// being in force; `None` when nothing changes any more.
///
/// For whoever caches a decision input (capabilities, a session): the cached value is valid until
/// this instant, never past it.
pub fn next_boundary<'a>(
    now: u64,
    grants: impl IntoIterator<Item = &'a Grant>,
    roles: impl IntoIterator<Item = &'a RoleAssignment>,
) -> Option<u64> {
    let grants = grants.into_iter().map(|g| g.validity());
    let roles = roles.into_iter().map(|r| r.validity());
    grants.chain(roles).filter_map(|v| v.next_boundary(now)).min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_is_inclusive_and_end_is_exclusive() {
        let window = Validity::between(10, 20).unwrap();
        assert!(!window.contains(9));
        assert!(window.contains(10));
        assert!(window.contains(19));
        assert!(!window.contains(20));
    }

    #[test]
    fn open_ended_windows() {
        let from = Validity {
            valid_from: Some(10),
            valid_until: None,
        };
        assert!(!from.contains(9) && from.contains(u64::MAX));
        let until = Validity {
            valid_from: None,
            valid_until: Some(10),
        };
        assert!(until.contains(0) && !until.contains(10));
    }

    #[test]
    fn inverted_and_empty_windows_are_refused() {
        assert_eq!(
            Validity::between(20, 10),
            Err(ValidityError::Inverted { from: 20, until: 10 })
        );
        assert!(Validity::between(10, 10).is_err());
        assert!(Validity::ALWAYS.check().is_ok());
    }

    #[test]
    fn boundary_is_strictly_after_now() {
        let window = Validity::between(10, 20).unwrap();
        assert_eq!(window.next_boundary(0), Some(10));
        assert_eq!(window.next_boundary(10), Some(20));
        assert_eq!(window.next_boundary(20), None);
        assert_eq!(Validity::ALWAYS.next_boundary(0), None);
    }

    #[test]
    fn without_now_only_unbounded_or_holding_items_are_in_force() {
        let window = Validity::between(10, 20).unwrap();
        assert!(!window.in_force(None, false));
        assert!(window.in_force(None, true));
        assert!(Validity::ALWAYS.in_force(None, false));
    }
}
