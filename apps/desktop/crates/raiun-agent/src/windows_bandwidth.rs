//! Exact-account preferences and one shared controller. No account authority is
//! derived from stored bytes; callers supply the verified scope and generation.
use raiun_engine::folder_pairs::AccountScope;
use raiun_opencloud::transfer_budget::{TransferBudget, TransferLimits};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
const MAX_BYTES: usize = 16 * 1024;
const MAX_REVISION: u64 = 9_007_199_254_740_991;
fn refused() -> String {
    "Bandwidth settings are unavailable or changed; refresh and try again".into()
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    account: String,
    model: AccountScope,
    bytes: Vec<u8>,
    token: String,
}
impl Scope {
    pub(super) fn new(
        profile: &str,
        server: &str,
        client: &str,
        issuer: Option<&str>,
        account: &str,
    ) -> Result<Self, String> {
        let server = url::Url::parse(server).map_err(|_| refused())?.to_string();
        let issuer = issuer
            .map(|s| url::Url::parse(s).map(|u| u.to_string()))
            .transpose()
            .map_err(|_| refused())?;
        let model = AccountScope::new(
            profile.into(),
            server.clone(),
            client.into(),
            issuer.clone(),
            account.into(),
        )
        .map_err(|_| refused())?;
        let bytes = serde_json::to_vec(&model).map_err(|_| refused())?;
        if bytes.len() > MAX_BYTES {
            return Err(refused());
        }
        let token = format!("{:x}", Sha256::digest(&bytes));
        Ok(Self {
            profile: profile.into(),
            server,
            client: client.into(),
            issuer,
            account: account.into(),
            model,
            bytes,
            token,
        })
    }
    pub(super) fn matches(
        &self,
        profile: &str,
        server: &str,
        client: &str,
        issuer: Option<&str>,
    ) -> bool {
        Self::new(profile, server, client, issuer, &self.account).is_ok_and(|scope| scope == *self)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub(super) trait Store {
    fn load(&self, scope: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn compare_exchange(&self, scope: &[u8], old: Option<&[u8]>, next: &[u8])
    -> Result<(), String>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    scope: AccountScope,
    revision: u64,
    limits: TransferLimits,
}
impl Record {
    fn decode(bytes: &[u8], scope: &Scope) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(refused());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| refused())?;
        if record.version != 1
            || record.scope != scope.model
            || record.revision == 0
            || record.revision > MAX_REVISION
        {
            return Err(refused());
        }
        record.limits.validate().map_err(|_| refused())?;
        Ok(record)
    }
}
struct Owner {
    scope: Scope,
    old: Option<Vec<u8>>,
    revision: u64,
    limits: TransferLimits,
    budget: TransferBudget,
    active_generation: Option<u64>,
}
#[derive(Default)]
pub(super) struct Service {
    owner: Mutex<Option<Owner>>,
    live: Mutex<Option<(u64, TransferBudget)>>,
    minimum_generation: AtomicU64,
    epoch: AtomicU64,
}
impl Service {
    pub(super) fn bind(
        &self,
        scope: Scope,
        generation: u64,
        store: &dyn Store,
    ) -> Result<TransferBudget, String> {
        self.bind_inner(scope, generation, store, true)
    }
    fn bind_inner(
        &self,
        scope: Scope,
        generation: u64,
        store: &dyn Store,
        activate: bool,
    ) -> Result<TransferBudget, String> {
        if generation == 0 {
            return Err(refused());
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let mut owner = self.owner.lock().map_err(|_| refused())?;
        let replacement = if owner.as_ref().is_none_or(|old| old.scope != scope) {
            let bytes = store.load(scope.bytes())?;
            let (revision, limits) = match bytes.as_deref() {
                Some(b) => {
                    let record = Record::decode(b, &scope)?;
                    (record.revision, record.limits)
                }
                None => (1, TransferLimits::default()),
            };
            let budget = TransferBudget::new();
            budget.set_limits(limits);
            budget.set_paused(true);
            Some(Owner {
                scope,
                old: bytes,
                revision,
                limits,
                budget,
                active_generation: None,
            })
        } else {
            None
        };
        let mut live = self.live.lock().map_err(|_| refused())?;
        if self.epoch.load(Ordering::Acquire) != epoch
            || generation < self.minimum_generation.load(Ordering::Acquire)
        {
            return Err(refused());
        }
        if let Some(replacement) = replacement {
            if let Some(old) = owner.as_ref() {
                old.budget.set_paused(true);
                old.budget.cancel_waiters();
            }
            *owner = Some(replacement);
        }
        let current = owner.as_ref().ok_or_else(refused)?;
        *live = Some((generation, current.budget.clone()));
        if activate {
            current.budget.set_paused(false);
        }
        Ok(current.budget.clone())
    }
    pub(super) fn scope(&self) -> Result<Option<Scope>, String> {
        Ok(self
            .owner
            .lock()
            .map_err(|_| refused())?
            .as_ref()
            .map(|o| o.scope.clone()))
    }
    pub(super) fn publish(&self, scope: &Scope, generation: u64) -> Result<(), String> {
        let mut owner = self.owner.lock().map_err(|_| refused())?;
        let live = self.live.lock().map_err(|_| refused())?;
        if generation < self.minimum_generation.load(Ordering::Acquire)
            || live
                .as_ref()
                .is_none_or(|(current, _)| *current != generation)
        {
            return Err(refused());
        }
        let current = owner
            .as_mut()
            .filter(|o| &o.scope == scope)
            .ok_or_else(refused)?;
        current.active_generation = Some(generation);
        Ok(())
    }
    // This lifecycle path never waits for preferences I/O or its owner mutex.
    pub(super) fn authorize_generation(&self, generation: u64) {
        self.minimum_generation
            .fetch_max(generation, Ordering::AcqRel);
        if let Ok(live) = self.live.lock()
            && let Some((old, budget)) = live.as_ref()
            && *old < generation
        {
            budget.set_paused(true);
            budget.cancel_waiters();
        }
    }
    pub(super) fn suspend(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        if let Ok(live) = self.live.lock()
            && let Some((_, budget)) = live.as_ref()
        {
            budget.set_paused(true);
            budget.cancel_waiters();
        }
    }
    pub(super) fn clear(&self) {
        self.suspend();
        if let Ok(mut owner) = self.owner.lock() {
            *owner = None;
        }
    }
    pub(super) fn value(&self, scope: Option<&Scope>, generation: u64) -> Result<Value, String> {
        let owner = self.owner.lock().map_err(|_| refused())?;
        let current = owner.as_ref().filter(|o| Some(&o.scope) == scope);
        Ok(match current {
            Some(o) => {
                json!({"limits":o.limits,"account_id":o.scope.account,"scope_token":o.scope.token,"revision":o.revision,"apply_immediately":o.active_generation == Some(generation) && !o.budget.is_paused()})
            }
            None => {
                json!({"limits":TransferLimits::default(),"account_id":Value::Null,"scope_token":Value::Null,"revision":1,"apply_immediately":false})
            }
        })
    }
    pub(super) fn update(
        &self,
        scope: &Scope,
        request: &Value,
        store: &dyn Store,
    ) -> Result<(), String> {
        let fields = request.as_object().ok_or_else(refused)?;
        if fields.keys().any(|k| {
            !matches!(
                k.as_str(),
                "action"
                    | "profile_id"
                    | "limits"
                    | "expected_account_id"
                    | "expected_revision"
                    | "expected_scope_token"
            )
        }) {
            return Err(refused());
        }
        let limits: TransferLimits =
            serde_json::from_value(fields.get("limits").cloned().ok_or_else(refused)?)
                .map_err(|_| refused())?;
        limits.validate().map_err(|_| refused())?;
        let mut owner = self.owner.lock().map_err(|_| refused())?;
        let o = owner
            .as_mut()
            .filter(|o| &o.scope == scope)
            .ok_or_else(refused)?;
        if fields.get("expected_account_id").and_then(Value::as_str) != Some(scope.account.as_str())
            || fields.get("expected_scope_token").and_then(Value::as_str)
                != Some(scope.token.as_str())
            || fields.get("expected_revision").and_then(Value::as_u64) != Some(o.revision)
        {
            return Err(refused());
        }
        let revision = o
            .revision
            .checked_add(1)
            .filter(|next| *next <= MAX_REVISION)
            .ok_or_else(refused)?;
        let next = serde_json::to_vec(&Record {
            version: 1,
            scope: scope.model.clone(),
            revision,
            limits,
        })
        .map_err(|_| refused())?;
        if next.len() > MAX_BYTES {
            return Err(refused());
        }
        store.compare_exchange(scope.bytes(), o.old.as_deref(), &next)?;
        o.old = Some(next);
        o.revision = revision;
        o.limits = limits;
        o.budget.set_limits(limits);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    #[derive(Default)]
    struct MemoryStore(Mutex<HashMap<Vec<u8>, Vec<u8>>>);
    impl Store for MemoryStore {
        fn load(&self, scope: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().get(scope).cloned())
        }
        fn compare_exchange(
            &self,
            scope: &[u8],
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), String> {
            let mut records = self.0.lock().unwrap();
            if records.get(scope).map(Vec::as_slice) != old {
                return Err(refused());
            }
            records.insert(scope.to_vec(), next.to_vec());
            Ok(())
        }
    }
    fn scope(client: &str, account: &str) -> Scope {
        Scope::new(
            "default",
            "https://example.test/",
            client,
            Some("https://issuer.test/"),
            account,
        )
        .unwrap()
    }
    fn request(scope: &Scope, revision: u64) -> Value {
        json!({"action":"bandwidth_limits_set","limits":{"upload_bytes_per_second":8192,"download_bytes_per_second":null},"expected_account_id":scope.account,"expected_scope_token":scope.token,"expected_revision":revision})
    }
    #[test]
    fn persisted_updates_share_controller_and_fence_scope_revision_and_stale_handles() {
        let store = MemoryStore::default();
        let service = Service::default();
        let a = scope("client-a", "subject");
        let first = service.bind(a.clone(), 1, &store).unwrap();
        let second = service.bind(a.clone(), 1, &store).unwrap();
        let client_a =
            raiun_opencloud::OpenCloudClient::new("https://example.test/", "synthetic-a".into())
                .unwrap()
                .with_transfer_budget(first.clone());
        let client_b =
            raiun_opencloud::OpenCloudClient::new("https://example.test/", "synthetic-b".into())
                .unwrap()
                .with_transfer_budget(second.clone());
        service.publish(&a, 1).unwrap();
        assert_eq!(
            service.value(Some(&a), 1).unwrap()["apply_immediately"],
            true
        );
        service.update(&a, &request(&a, 1), &store).unwrap();
        assert_eq!(first.limits(), second.limits());
        assert_eq!(
            client_a.transfer_budget().limits(),
            client_b.transfer_budget().limits()
        );
        assert_eq!(
            client_a
                .transfer_budget()
                .limits()
                .upload_bytes_per_second
                .unwrap()
                .get(),
            8192
        );
        assert_eq!(first.limits().upload_bytes_per_second.unwrap().get(), 8192);
        assert!(service.update(&a, &request(&a, 1), &store).is_err());
        let restarted = Service::default();
        let restored = restarted.bind(a.clone(), 2, &store).unwrap();
        assert_eq!(restored.limits(), first.limits());
        assert_eq!(restarted.value(Some(&a), 2).unwrap()["revision"], 2);
        assert_eq!(
            restarted.value(Some(&a), 2).unwrap()["apply_immediately"],
            false
        );
        // Different client with the SAME subject and initial revision cannot accept old UI authority.
        let b = scope("client-b", "subject");
        let fresh = service.bind(b.clone(), 3, &store).unwrap();
        assert!(first.is_paused());
        assert_eq!(fresh.limits(), TransferLimits::default());
        assert!(service.update(&b, &request(&a, 1), &store).is_err());
        assert!(service.update(&a, &request(&a, 1), &store).is_err());
        assert_eq!(fresh.limits(), TransferLimits::default());
        // Cross-handle CAS fails without changing the live controller.
        restarted.update(&a, &request(&a, 2), &store).unwrap();
        let stale = Service::default();
        let stale_budget = stale.bind(a.clone(), 4, &store).unwrap();
        restarted.update(&a, &request(&a, 3), &store).unwrap();
        let mut stale_request = request(&a, 3);
        stale_request["limits"]["upload_bytes_per_second"] = json!(16384);
        assert!(stale.update(&a, &stale_request, &store).is_err());
        assert_eq!(stale.value(Some(&a), 4).unwrap()["revision"], 3);
        assert_eq!(
            stale_budget.limits().upload_bytes_per_second.unwrap().get(),
            8192
        );
        let old_stream = fresh.cancellation();
        service.suspend();
        assert!(fresh.is_paused());
        let resumed = service.bind(b.clone(), 4, &store).unwrap();
        assert!(!resumed.is_paused());
        assert!(old_stream.is_cancelled());
        assert!(!resumed.cancellation().is_cancelled());
        service.authorize_generation(5);
        let current = service.bind(b.clone(), 5, &store).unwrap();
        assert!(service.bind(a.clone(), 4, &store).is_err());
        assert!(service.bind(b.clone(), 4, &store).is_err());
        assert!(!current.is_paused());
        assert!(service.scope().unwrap() == Some(b.clone()));
        service.suspend();
        service.bind_inner(b.clone(), 5, &store, false).unwrap();
        assert!(resumed.is_paused());
        service.clear();
        assert!(service.scope().unwrap().is_none());
        let invalid = Record {
            version: 1,
            scope: a.model.clone(),
            revision: 0,
            limits: TransferLimits::default(),
        };
        assert!(Record::decode(&serde_json::to_vec(&invalid).unwrap(), &a).is_err());
        assert!(
            Record::decode(
                &serde_json::to_vec(&Record {
                    revision: MAX_REVISION + 1,
                    ..invalid
                })
                .unwrap(),
                &a
            )
            .is_err()
        );
        assert!(a.matches(
            "default",
            "https://example.test/",
            "client-a",
            Some("https://issuer.test/")
        ));
        assert!(!a.matches(
            "default",
            "https://foreign.test/",
            "client-a",
            Some("https://issuer.test/")
        ));
    }
}
