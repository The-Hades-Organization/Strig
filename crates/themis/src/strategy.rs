use crate::grant::{Effect, Grant};

/// Grant aplicável ao pedido, com a posição do degrau em que casou (0 = mais específico).
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub grant: Grant,
    pub rank: usize,
}

/// Combina os grants aplicáveis numa decisão. Devolve o índice do candidato decisivo, ou
/// `None` para cair no default-deny.
pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn combine(&self, candidates: &[Candidate]) -> Option<usize>;
}

fn first(candidates: &[Candidate], effect: Effect, filter: impl Fn(&Candidate) -> bool) -> Option<usize> {
    candidates.iter().position(|c| c.grant.effect == effect && filter(c))
}

/// O degrau mais específico com algum grant decide; nele, `deny` vence `allow`. É o padrão do
/// motor.
#[derive(Debug, Clone, Copy, Default)]
pub struct MostSpecific;

impl Strategy for MostSpecific {
    fn name(&self) -> &'static str {
        "most_specific"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        let best = candidates.iter().map(|c| c.rank).min()?;
        first(candidates, Effect::Deny, |c| c.rank == best)
            .or_else(|| first(candidates, Effect::Allow, |c| c.rank == best))
    }
}

/// Qualquer `deny` vence, em qualquer degrau.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyOverrides;

impl Strategy for DenyOverrides {
    fn name(&self) -> &'static str {
        "deny_overrides"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        first(candidates, Effect::Deny, |_| true).or_else(|| first(candidates, Effect::Allow, |_| true))
    }
}

/// Qualquer `allow` vence, em qualquer degrau.
#[derive(Debug, Clone, Copy, Default)]
pub struct PermitOverrides;

impl Strategy for PermitOverrides {
    fn name(&self) -> &'static str {
        "permit_overrides"
    }

    fn combine(&self, candidates: &[Candidate]) -> Option<usize> {
        first(candidates, Effect::Allow, |_| true).or_else(|| first(candidates, Effect::Deny, |_| true))
    }
}

/// O primeiro grant aplicável, na ordem da fonte, decide.
#[derive(Debug, Clone, Copy, Default)]
pub struct FirstApplicable;

impl Strategy for FirstApplicable {
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
