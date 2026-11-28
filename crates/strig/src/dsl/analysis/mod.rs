//! Static analysis of a policy, in the vocabulary of Strig: what changes between two versions
//! ([`diff`]) and what is dead or suspicious in one ([`lint`]).
//!
//! Both are pure: no IO, no clock. [`diff`] asks the engine of each version the same questions and
//! lists the ones whose answer flips; [`lint`] reads the policy as data and reports findings with
//! a stable code, a severity, the position in the source and a hint.

mod diff;
mod lint;

pub use diff::{
    ChangeKind, DecisionChange, DiffError, DiffFixture, DiffOptions, DiffSide, MAX_FIXTURE_BYTES, PolicyDiff,
    Responsible, Universe, diff,
};
pub use lint::{Finding, LintCode, LintOptions, Severity, lint};

#[cfg(test)]
mod tests;
