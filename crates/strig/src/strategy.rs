use crate::grant::{Effect, Grant};

/// Grant applicable to the request, with the position of the step where it matched (0 = most specific).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Candidate {
    pub grant: Grant,
    pub rank: usize,
}

/// The strategies of this crate, which a listing ([`crate::Engine::list`]) reproduces as a
/// structural expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeStrategy {
    MostSpecific,
    DenyOverrides,
    PermitOverrides,
    FirstApplicable,
}

/// Combines the applicable grants into a decision. Returns the index of the deciding candidate, or
/// `None` to fall back to default-deny.
pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn combine(&self, candidates: &[Candidate]) -> Option<usize>;

    /// Which strategy of this crate this is, if it is one. A listing reproduces only the strategies
    /// that answer here; any other is left as a residue to check row by row, whatever its
    /// [`Strategy::name`] says. The default is `None`: a strategy of yours, or a wrapper around one
    /// of these, stays residue unless it answers on purpose.
    fn native(&self) -> Option<NativeStrategy> {
        None
    }
}

fn first(candidates: &[Candidate], effect: Effect, filter: impl Fn(&Candidate) -> bool) -> Option<usize> {
    candidates.iter().position(|c| c.grant.effect == effect && filter(c))
}

/// The most specific step with any grant decides; within it, `deny` beats `allow`. This is the
/// engine's default.
#[derive(Debug, Clone, Copy, Default)]
pub struct MostSpecific;

impl Strategy for MostSpecific {
    fn native(&self) -> Option<NativeStrategy> {
        Some(NativeStrategy::MostSpecific)
    }

    fn name(&self) -> &'static str {
        "most_specific"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        let best = candidates.iter().map(|c| c.rank).min()?;
        first(candidates, Effect::Deny, |c| c.rank == best)
            .or_else(|| first(candidates, Effect::Allow, |c| c.rank == best))
    }
}

/// Any `deny` wins, at any step.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyOverrides;

impl Strategy for DenyOverrides {
    fn native(&self) -> Option<NativeStrategy> {
        Some(NativeStrategy::DenyOverrides)
    }

    fn name(&self) -> &'static str {
        "deny_overrides"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        first(candidates, Effect::Deny, |_| true).or_else(|| first(candidates, Effect::Allow, |_| true))
    }
}

/// Any `allow` wins, at any step.
#[derive(Debug, Clone, Copy, Default)]
pub struct PermitOverrides;

impl Strategy for PermitOverrides {
    fn native(&self) -> Option<NativeStrategy> {
        Some(NativeStrategy::PermitOverrides)
    }

    fn name(&self) -> &'static str {
        "permit_overrides"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        first(candidates, Effect::Allow, |_| true).or_else(|| first(candidates, Effect::Deny, |_| true))
    }
}

/// The first applicable grant, in source order, decides.
///
/// "Source order" is the order of [`crate::GrantSource::visit`]. A listing reads the grants through
/// [`crate::GrantIndex`], which must keep that relative order.
#[derive(Debug, Clone, Copy, Default)]
pub struct FirstApplicable;

impl Strategy for FirstApplicable {
    fn native(&self) -> Option<NativeStrategy> {
        Some(NativeStrategy::FirstApplicable)
    }

    fn name(&self) -> &'static str {
        "first_applicable"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        (!candidates.is_empty()).then_some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{SubjectMatcher, TargetSelector};

    fn c(effect: Effect, rank: usize) -> Candidate {
        Candidate {
            grant: Grant::new("g", effect, SubjectMatcher::Any, "p", TargetSelector::global()),
            rank,
        }
    }

    #[test]
    fn most_specific_prefers_lower_rank_then_deny() {
        let set = [c(Effect::Deny, 3), c(Effect::Allow, 1), c(Effect::Deny, 1)];
        assert_eq!(MostSpecific.combine(&set), Some(2));
        let set = [c(Effect::Deny, 3), c(Effect::Allow, 1)];
        assert_eq!(MostSpecific.combine(&set), Some(1));
    }

    #[test]
    fn overrides_ignore_rank() {
        let set = [c(Effect::Allow, 0), c(Effect::Deny, 4)];
        assert_eq!(DenyOverrides.combine(&set), Some(1));
        assert_eq!(PermitOverrides.combine(&set), Some(0));
        assert_eq!(FirstApplicable.combine(&set), Some(0));
        assert_eq!(MostSpecific.combine(&[]), None);
    }
}
