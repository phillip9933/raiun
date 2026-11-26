//! Last-observed native activity only. No storage, scheduling or authority.
use super::*;
use serde::Serialize;
use windows_namespace_dispatcher::ActivitySnapshot;

#[derive(Default)]
pub(super) struct Cache {
    epoch: AtomicU64,
    exhausted: AtomicBool,
    sample: Mutex<Option<Sample>>,
}
#[derive(Clone)]
pub(super) struct Owner {
    epoch: u64,
    binding: ActiveProviderBinding,
}
#[derive(Clone, Copy, Default)]
struct Totals {
    // Successfully published completed drain/tick observations, including
    // polls. These are sampled work durations, not wall time or throughput.
    count: u64,
    total_ms: u64,
    max_ms: u64,
}
struct Sample {
    owner: Owner,
    observed: Instant,
    in_progress: bool,
    last_ms: Option<u64>,
    totals: Option<Totals>,
    activity: ActivitySnapshot,
}
#[derive(Serialize)]
pub(super) struct Observation {
    #[serde(skip)]
    owner: Option<Owner>,
    state: &'static str,
    observation_age_ms: Option<u64>,
    owner_step_in_progress: Option<bool>,
    last_owner_step_ms: Option<u64>,
    owner_steps_observed: Option<u64>,
    owner_step_total_ms: Option<u64>,
    owner_step_max_ms: Option<u64>,
    activity: Option<ActivitySnapshot>,
}
impl Observation {
    pub(super) fn unavailable() -> Self {
        Self {
            owner: None,
            state: "unavailable",
            observation_age_ms: None,
            owner_step_in_progress: None,
            last_owner_step_ms: None,
            owner_steps_observed: None,
            owner_step_total_ms: None,
            owner_step_max_ms: None,
            activity: None,
        }
    }
}
impl Cache {
    fn advance_epoch(&self) -> Option<u64> {
        if self.exhausted.load(Ordering::Acquire) {
            return None;
        }
        let mut previous = self.epoch.load(Ordering::Acquire);
        loop {
            let Some(next) = previous.checked_add(1) else {
                self.exhausted.store(true, Ordering::Release);
                return None;
            };
            match self.epoch.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(next),
                Err(current) => previous = current,
            }
        }
    }
    pub(super) fn retire(&self) {
        let _ = self.advance_epoch();
        if let Ok(mut sample) = self.sample.try_lock() {
            *sample = None;
        }
    }
    pub(super) fn bind(&self, binding: &ActiveProviderBinding) -> Option<Owner> {
        let epoch = self.advance_epoch()?;
        if let Ok(mut sample) = self.sample.try_lock() {
            *sample = None;
        }
        Some(Owner {
            epoch,
            binding: binding.clone(),
        })
    }
    fn current(&self, owner: &Owner, generation: &AtomicU64, connected: &AtomicBool) -> bool {
        !self.exhausted.load(Ordering::Acquire)
            && owner.epoch == self.epoch.load(Ordering::Acquire)
            && owner.binding.generation != 0
            && owner.binding.generation == generation.load(Ordering::Acquire)
            && connected.load(Ordering::Acquire)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish(
        &self,
        owner: &Owner,
        binding: &ActiveProviderBinding,
        generation: &AtomicU64,
        connected: &AtomicBool,
        activity: ActivitySnapshot,
        in_progress: bool,
        elapsed: Option<Duration>,
    ) {
        if activity.executor.is_none() || activity.create_last_wait.is_none() {
            return;
        }
        if &owner.binding != binding || !self.current(owner, generation, connected) {
            return;
        }
        let Ok(mut cache) = self.sample.try_lock() else {
            return;
        };
        if !self.current(owner, generation, connected) {
            return;
        }
        let old = cache.as_ref().filter(|old| old.owner.epoch == owner.epoch);
        let mut totals = old.map_or(Some(Totals::default()), |old| old.totals);
        let mut last_ms = old.and_then(|old| old.last_ms);
        if let Some(elapsed) = elapsed {
            last_ms = u64::try_from(elapsed.as_millis()).ok();
            totals = totals.zip(last_ms).and_then(|(old, ms)| {
                Some(Totals {
                    count: old.count.checked_add(1)?,
                    total_ms: old.total_ms.checked_add(ms)?,
                    max_ms: old.max_ms.max(ms),
                })
            });
        }
        *cache = Some(Sample {
            owner: owner.clone(),
            observed: Instant::now(),
            in_progress,
            last_ms,
            totals,
            activity,
        });
    }
    pub(super) fn snapshot(
        &self,
        binding: &ActiveProviderBinding,
        generation: &AtomicU64,
        connected: &AtomicBool,
    ) -> Observation {
        let Ok(cache) = self.sample.try_lock() else {
            return Observation::unavailable();
        };
        let Some(sample) = cache.as_ref().filter(|sample| {
            &sample.owner.binding == binding && self.current(&sample.owner, generation, connected)
        }) else {
            return Observation::unavailable();
        };
        // Clone fixed-size/bounded observations only. Serialization and all
        // owner work occur after this lock is released.
        let observation = Observation {
            owner: Some(sample.owner.clone()),
            state: "observed",
            observation_age_ms: u64::try_from(sample.observed.elapsed().as_millis()).ok(),
            owner_step_in_progress: Some(sample.in_progress),
            last_owner_step_ms: sample.last_ms,
            owner_steps_observed: sample.totals.map(|t| t.count),
            owner_step_total_ms: sample.totals.map(|t| t.total_ms),
            owner_step_max_ms: sample.totals.map(|t| t.max_ms),
            activity: Some(sample.activity.clone()),
        };
        if !self.current(&sample.owner, generation, connected) {
            return Observation::unavailable();
        }
        observation
    }
}

pub(super) fn status(agent: &WindowsAgent, state: &AccountState) -> Observation {
    let Some(binding) = current_binding(agent, state) else {
        return Observation::unavailable();
    };
    agent.provider.native_activity.snapshot(
        &binding,
        &agent.provider.authorized_generation,
        &agent.provider.connected,
    )
}

pub(super) fn still_current(
    agent: &WindowsAgent,
    state: &AccountState,
    observation: &Observation,
) -> bool {
    observation.owner.as_ref().is_some_and(|owner| {
        current_binding(agent, state).as_ref() == Some(&owner.binding)
            && agent.provider.native_activity.current(
                owner,
                &agent.provider.authorized_generation,
                &agent.provider.connected,
            )
    })
}

fn current_binding(agent: &WindowsAgent, state: &AccountState) -> Option<ActiveProviderBinding> {
    let Ok(preference) = agent.provider.mount_preference.try_lock() else {
        return None;
    };
    if !*preference
        || !agent.provider.is_connected()
        || !state.online_authenticated
        || state.offline_cached
        || state.active_generation == 0
        || state.active_generation != agent.generation.load(Ordering::Acquire)
        || state.active_generation != agent.provider.authorized_generation.load(Ordering::Acquire)
        || state.authenticating
        || state.refreshing
        || state.logout_pending
        || state.retiring
        || state.session_cleanup_uncertain
    {
        return None;
    }
    let root = state
        .root_configuration
        .as_ref()
        .filter(|root| root.valid)?;
    let session = state.session.as_ref()?;
    if root.profile_scope != agent.profile_scope
        || root.server != session.server
        || root.client_id != session.client_id
    {
        return None;
    }
    let registration = root
        .registration_ownership
        .as_ref()
        .filter(|owner| owner.state == "registered")?;
    let personal_root = registration.personal_root_resource_id.as_ref()?;
    let binding = ActiveProviderBinding {
        generation: state.active_generation,
        path: PathBuf::from(&root.path),
        identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: root.volume_serial,
            file_index: root.file_index,
        },
        personal_space_id: registration.personal_drive_id.clone(),
        personal_root_resource_id: personal_root.clone(),
    };
    Some(binding)
}
