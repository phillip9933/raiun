//! Independent ordinary file claims; exclusive namespace operations still fence
//! the entire set. Native identity, capture and conditional write checks remain
//! with the connection owner, never with these bookkeeping keys.
use super::*;

pub(super) struct Claim {
    id: u64,
    components: Vec<String>,
    dispatched: bool,
    completed: bool,
}

pub(crate) struct IndependentCreateAdmission {
    tracker: Arc<CloseCaptureAdmission>,
    id: u64,
    epoch: u64,
    observation: u64,
    dispatched: bool,
    completed: bool,
    dispatch: Arc<dyn Fn() -> bool + Send + Sync>,
    lifetime: DispatchProbeLifetime,
    _owner_thread: PhantomData<Rc<()>>,
}

pub(crate) enum IndependentCreateAdmissionError {
    Busy,
    Refused,
}

impl CloseCaptureAdmission {
    pub(crate) fn try_begin_independent_create(
        self: &Arc<Self>,
        components: Vec<String>,
    ) -> Result<IndependentCreateAdmission, IndependentCreateAdmissionError> {
        let mut state = self
            .try_state()
            .ok_or(IndependentCreateAdmissionError::Refused)?;
        if self.unknown.load(Ordering::Acquire) {
            return Err(IndependentCreateAdmissionError::Refused);
        }
        if state.active_closes != 0
            || state.rename_claimed
            || state.ordinary_creates.len() >= 4
            || state.ordinary_creates.iter().any(|claim| {
                claim
                    .components
                    .iter()
                    .zip(&components)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
        {
            return Err(IndependentCreateAdmissionError::Busy);
        }
        let id = state
            .create_nonce
            .checked_add(1)
            .ok_or(IndependentCreateAdmissionError::Refused)?;
        state.create_nonce = id;
        let observation = self.create_observation.load(Ordering::Acquire);
        let (dispatch, lifetime) = DispatchProbeLifetime::new(self.clone(), observation);
        state.ordinary_creates.push(Claim {
            id,
            components,
            dispatched: false,
            completed: false,
        });
        Ok(IndependentCreateAdmission {
            tracker: self.clone(),
            id,
            epoch: state.dirty_epoch,
            observation,
            dispatched: false,
            completed: false,
            dispatch,
            lifetime,
            _owner_thread: PhantomData,
        })
    }
}

impl IndependentCreateAdmission {
    fn matches(&self, state: &State) -> bool {
        !self.tracker.unknown.load(Ordering::Acquire)
            && state.active_closes == 0
            && !state.rename_claimed
            && state.dirty_epoch == self.epoch
            && self.tracker.create_observation.load(Ordering::Acquire) == self.observation
            && state.ordinary_creates.iter().any(|claim| {
                claim.id == self.id
                    && claim.dispatched == self.dispatched
                    && claim.completed == self.completed
            })
    }
    pub(crate) fn is_current(&self) -> bool {
        self.tracker
            .try_state()
            .is_some_and(|state| self.matches(&state))
    }
    pub(crate) fn observation_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.lifetime.observation_probe()
    }
    pub(crate) fn dispatch_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.dispatch.clone()
    }
    pub(crate) fn claim_dispatch(&mut self) -> bool {
        let Some(mut state) = self.tracker.try_state() else {
            return false;
        };
        if self.dispatched || !self.matches(&state) {
            return false;
        }
        let Some(claim) = state
            .ordinary_creates
            .iter_mut()
            .find(|claim| claim.id == self.id)
        else {
            return false;
        };
        claim.dispatched = true;
        self.dispatched = true;
        if !self.lifetime.arm_after_dispatch() {
            self.tracker.mark_unknown();
            return false;
        }
        true
    }
    pub(crate) fn claim_completion(&mut self) -> bool {
        let Some(mut state) = self.tracker.try_state() else {
            return false;
        };
        if !self.dispatched || self.completed || !self.matches(&state) {
            return false;
        }
        let Some(claim) = state
            .ordinary_creates
            .iter_mut()
            .find(|claim| claim.id == self.id)
        else {
            return false;
        };
        claim.completed = true;
        self.completed = true;
        true
    }
}

impl Drop for IndependentCreateAdmission {
    fn drop(&mut self) {
        // Retire this exact claim only. A sibling completion must not revoke
        // other immutable captures; actual closes still advance the global epoch.
        self.lifetime.live.store(false, Ordering::Release);
        let Some(mut state) = self.tracker.try_state() else {
            return;
        };
        let Some(index) = state
            .ordinary_creates
            .iter()
            .position(|claim| claim.id == self.id)
        else {
            self.tracker.mark_unknown();
            return;
        };
        let claim = state.ordinary_creates.remove(index);
        if claim.dispatched != self.dispatched || claim.completed != self.completed {
            self.tracker.mark_unknown();
        }
    }
}
