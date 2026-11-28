//! Elevations in real time: an approved or revoked elevation is a [`Change`], and its end is an
//! expiry notice at the instant, as for the windows of grants the [`CapabilityCache`](crate::CapabilityCache) tracks.

use strig::{Anchor, ElevationTarget, PendingRequest};

use crate::{Change, ChangeKind, Hub, TransportError};

/// The [`Change`] an elevation causes: the grants or the roles of its actor under the scope of the
/// elevation, with the request id on it. `None` when `request` carries no elevation or its actor has
/// no id.
pub fn elevation_change(request: &PendingRequest) -> Option<Change> {
    let info = request.elevation.as_ref()?;
    let subject = request.actor.id.clone()?;
    let (kind, scope) = match &info.target {
        ElevationTarget::Role { scope, .. } => (ChangeKind::Roles, scope),
        ElevationTarget::Permission { scope, .. } => (ChangeKind::Grants, scope),
        _ => return None,
    };
    let scope = scope.clone().unwrap_or_else(Anchor::global);
    Some(
        Change::new(kind, scope)
            .for_subject(subject)
            .with_id(request.id.clone()),
    )
}

impl Hub {
    /// An elevation was approved (or applied by break-glass): publishes its [`Change`] and schedules
    /// the expiry notice at `valid_until`, so sessions and caches drop it at the instant. `now_ms`
    /// is the clock of the caller, as in [`Hub::schedule_expiry`]. Returns the published change, or
    /// `None` for a request that is no elevation.
    pub async fn elevation_approved(
        &self,
        request: &PendingRequest,
        now_ms: u64,
    ) -> Result<Option<Change>, TransportError> {
        let Some(change) = elevation_change(request) else {
            return Ok(None);
        };
        if let (Some(subject), Some(until)) = (
            request.actor.id.as_deref(),
            request.elevation.as_ref().and_then(|info| info.valid_until),
        ) {
            self.schedule_expiry(until, now_ms, Change::expiry(subject));
        }
        self.publish(change).await.map(Some)
    }

    /// An elevation was revoked before its time: publishes its [`Change`]. The expiry notice already
    /// scheduled still fires, harmlessly.
    pub async fn elevation_revoked(&self, request: &PendingRequest) -> Result<Option<Change>, TransportError> {
        match elevation_change(request) {
            Some(change) => self.publish(change).await.map(Some),
            None => Ok(None),
        }
    }
}
