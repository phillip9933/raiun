//! Reconnect-only, profile-owned proxy preferences. Callers retain auth/lifecycle authority.
use raiun_engine::folder_pairs::AccountScope;
use raiun_opencloud::ProxyConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
const MAX_BYTES: usize = 16 * 1024;
const MAX_REVISION: u64 = 9_007_199_254_740_991;
fn refused() -> String {
    "Proxy settings are unavailable or changed; refresh and try again".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}
impl Owner {
    fn model(&self) -> Result<AccountScope, String> {
        AccountScope::new(
            self.profile.clone(),
            self.server.clone(),
            self.client.clone(),
            self.issuer.clone(),
            self.subject.clone(),
        )
        .map_err(|_| refused())
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.model()?).map_err(|_| refused())
    }
    fn from_trusted(scope: &[u8], profile: &str) -> Result<Self, String> {
        let owner: Self = serde_json::from_slice(scope).map_err(|_| refused())?;
        if owner.profile != profile || owner.bytes()? != scope {
            return Err(refused());
        }
        Ok(owner)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    profile: String,
    revision: u64,
    owner: Option<Owner>,
    proxy: ProxyConfig,
}
impl Record {
    fn default_for(profile: &str) -> Self {
        Self {
            version: 1,
            profile: profile.into(),
            revision: 1,
            owner: None,
            proxy: ProxyConfig::System,
        }
    }
    fn decode(bytes: &[u8], profile: &str) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(refused());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| refused())?;
        if record.version != 1
            || record.profile != profile
            || record.revision == 0
            || record.revision > MAX_REVISION
        {
            return Err(refused());
        }
        if let Some(owner) = &record.owner {
            if owner.profile != profile {
                return Err(refused());
            }
            owner.model()?;
        }
        record.proxy.validate().map_err(|_| refused())?;
        Ok(record)
    }
    fn reply(&self, current: Option<&[u8]>) -> Result<Value, String> {
        let owned = match (&self.owner, current) {
            (Some(owner), Some(scope)) => owner.bytes()? == scope,
            _ => false,
        };
        let proxy = if self.owner.is_none() || owned {
            self.proxy.clone()
        } else {
            ProxyConfig::System
        };
        Ok(
            json!({"proxy":proxy,"account_id":if owned {self.owner.as_ref().map(|owner|owner.subject.as_str())}else{None},"scope_token":if owned {Some(format!("{:x}",Sha256::digest(current.ok_or_else(refused)?)))}else{None},"revision":self.revision,"apply_requires_reconnect":true}),
        )
    }
    fn next(&mut self) -> Result<(), String> {
        self.revision = self
            .revision
            .checked_add(1)
            .filter(|next| *next <= MAX_REVISION)
            .ok_or_else(refused)?;
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|_| refused())?;
        if bytes.len() > MAX_BYTES {
            return Err(refused());
        }
        Ok(bytes)
    }
}
pub(super) trait Store {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;
    fn compare_exchange(&self, old: Option<&[u8]>, next: &[u8]) -> Result<(), String>;
}
struct PendingAuth {
    generation: u64,
    raw: Option<Vec<u8>>,
    route: ProxyConfig,
}
#[derive(Default)]
pub(super) struct Service {
    serial: Mutex<Option<PendingAuth>>,
}
impl Service {
    fn load(profile: &str, store: &dyn Store) -> Result<(Option<Vec<u8>>, Record), String> {
        let bytes = store.load()?;
        let record = match &bytes {
            Some(bytes) => Record::decode(bytes, profile)?,
            None => Record::default_for(profile),
        };
        Ok((bytes, record))
    }
    pub(super) fn value(
        &self,
        profile: &str,
        current: Option<&[u8]>,
        store: &dyn Store,
    ) -> Result<Value, String> {
        let _serial = self.serial.lock().map_err(|_| refused())?;
        let (_, record) = Self::load(profile, store)?;
        record.reply(current)
    }
    /// Snapshot before auth network I/O. A prior bound account never chooses a new account's route.
    pub(super) fn auth_proxy(
        &self,
        profile: &str,
        generation: u64,
        store: &dyn Store,
    ) -> Result<ProxyConfig, String> {
        if generation == 0 {
            return Err(refused());
        }
        let mut serial = self.serial.lock().map_err(|_| refused())?;
        let (raw, record) = Self::load(profile, store)?;
        let route = if record.owner.is_none() {
            record.proxy
        } else {
            ProxyConfig::System
        };
        *serial = Some(PendingAuth {
            generation,
            raw,
            route: route.clone(),
        });
        Ok(route)
    }
    /// Only a real verified metadata scope may bind the pending route used for auth.
    /// Foreign bound bytes or a concurrently changed route remain inactive and unchanged.
    pub(super) fn bind_verified(
        &self,
        profile: &str,
        scope: &[u8],
        route: &ProxyConfig,
        generation: u64,
        store: &dyn Store,
    ) -> Result<(), String> {
        let owner = Owner::from_trusted(scope, profile)?;
        let serial = self.serial.lock().map_err(|_| refused())?;
        let (old, mut record) = Self::load(profile, store)?;
        if serial.as_ref().is_none_or(|snapshot| {
            snapshot.generation != generation || snapshot.raw != old || snapshot.route != *route
        }) || record.owner.is_some()
            || record.proxy != *route
        {
            return Ok(());
        }
        record.owner = Some(owner);
        record.next()?;
        store.compare_exchange(old.as_deref(), &record.encode()?)
    }
    pub(super) fn update(
        &self,
        profile: &str,
        request: &Value,
        store: &dyn Store,
    ) -> Result<Value, String> {
        let fields = request.as_object().ok_or_else(refused)?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action"
                    | "profile_id"
                    | "proxy"
                    | "expected_account_id"
                    | "expected_scope_token"
                    | "expected_revision"
            )
        }) {
            return Err(refused());
        }
        let proxy: ProxyConfig =
            serde_json::from_value(fields.get("proxy").cloned().ok_or_else(refused)?)
                .map_err(|_| refused())?;
        proxy.validate().map_err(|_| refused())?;
        let mut serial = self.serial.lock().map_err(|_| refused())?;
        let (old, mut record) = Self::load(profile, store)?;
        let reply = record.reply(None)?;
        if fields.get("expected_revision").and_then(Value::as_u64) != Some(record.revision)
            || fields.get("expected_account_id") != Some(&reply["account_id"])
        {
            return Err(refused());
        }
        if fields
            .get("expected_scope_token")
            .is_some_and(|value| !value.is_null())
        {
            return Err(refused());
        }
        record.owner = None;
        record.proxy = proxy;
        record.next()?;
        store.compare_exchange(old.as_deref(), &record.encode()?)?;
        *serial = None;
        record.reply(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct MemoryStore(Mutex<Option<Vec<u8>>>);
    impl Store for MemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn compare_exchange(&self, old: Option<&[u8]>, next: &[u8]) -> Result<(), String> {
            let mut bytes = self.0.lock().unwrap();
            if bytes.as_deref() != old {
                return Err(refused());
            }
            *bytes = Some(next.to_vec());
            Ok(())
        }
    }
    fn scope(subject: &str) -> Vec<u8> {
        serde_json::to_vec(
            &AccountScope::new(
                "default".into(),
                "https://example.test/".into(),
                "client".into(),
                None,
                subject.into(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn request(revision: u64, account: Value, token: Value, proxy: Value) -> Value {
        json!({"action":"network_proxy_set","expected_revision":revision,"expected_account_id":account,"expected_scope_token":token,"proxy":proxy})
    }
    #[test]
    fn explicit_pending_route_reopens_and_only_verified_owner_binds_with_revision_fence() {
        let service = Service::default();
        let store = MemoryStore::default();
        let a = scope("subject-a");
        let initial = service.value("default", None, &store).unwrap();
        assert_eq!(initial["revision"], 1);
        assert!(initial["account_id"].is_null());
        assert_eq!(
            service.auth_proxy("default", 1, &store).unwrap(),
            ProxyConfig::System
        );
        let pending = service
            .update(
                "default",
                &request(1, Value::Null, Value::Null, json!({"mode":"direct"})),
                &store,
            )
            .unwrap();
        assert_eq!(pending["revision"], 2);
        let reopened = Service::default();
        let route = reopened.auth_proxy("default", 1, &store).unwrap();
        assert_eq!(route, ProxyConfig::Direct);
        reopened
            .bind_verified("default", &a, &route, 1, &store)
            .unwrap();
        let bound = reopened.value("default", Some(&a), &store).unwrap();
        assert_eq!(bound["revision"], 3);
        assert_eq!(bound["account_id"], "subject-a");
        assert!(
            reopened
                .update(
                    "default",
                    &request(2, Value::Null, Value::Null, json!({"mode":"system"})),
                    &store
                )
                .is_err()
        );
        reopened
            .bind_verified("default", &a, &route, 1, &store)
            .unwrap();
        assert_eq!(
            reopened.value("default", Some(&a), &store).unwrap()["revision"],
            3
        );
        let old = store.load().unwrap();
        let b = scope("subject-b");
        reopened
            .bind_verified("default", &b, &ProxyConfig::System, 2, &store)
            .unwrap();
        assert_eq!(store.load().unwrap(), old);
        assert_eq!(
            reopened.auth_proxy("default", 1, &store).unwrap(),
            ProxyConfig::System
        );
        assert!(reopened.value("default", Some(&b), &store).unwrap()["account_id"].is_null());
        let stale = request(
            3,
            json!("subject-a"),
            bound["scope_token"].clone(),
            json!({"mode":"system"}),
        );
        assert!(reopened.update("default", &stale, &store).is_err());
        assert_eq!(store.load().unwrap(), old);
        // Deliberate signed-out policy replacement is explicit, never an automatic rebind.
        reopened
            .update(
                "default",
                &request(3, Value::Null, Value::Null, json!({"mode":"direct"})),
                &store,
            )
            .unwrap();
        assert_eq!(
            reopened.auth_proxy("default", 1, &store).unwrap(),
            ProxyConfig::Direct
        );
        let pending_b = store.load().unwrap();
        reopened.auth_proxy("default", 2, &store).unwrap();
        reopened
            .bind_verified("default", &a, &ProxyConfig::Direct, 1, &store)
            .unwrap();
        assert_eq!(store.load().unwrap(), pending_b);
        reopened
            .bind_verified("default", &b, &ProxyConfig::Direct, 2, &store)
            .unwrap();
        assert_eq!(
            reopened.value("default", Some(&b), &store).unwrap()["account_id"],
            "subject-b"
        );
    }
    #[test]
    fn malformed_foreign_and_credential_proxy_fail_without_reset_or_publication() {
        let service = Service::default();
        let store = MemoryStore::default();
        let before = store.load().unwrap();
        assert!(
            service
                .update(
                    "default",
                    &request(
                        1,
                        Value::Null,
                        Value::Null,
                        json!({"mode":"explicit","url":"http://user:password@example.test"})
                    ),
                    &store
                )
                .is_err()
        );
        assert_eq!(store.load().unwrap(), before);
        *store.0.lock().unwrap() = Some(b"{broken".to_vec());
        let malformed = store.load().unwrap();
        assert!(service.auth_proxy("default", 1, &store).is_err());
        assert_eq!(store.load().unwrap(), malformed);
        let mut record = Record::default_for("foreign-profile");
        *store.0.lock().unwrap() = Some(record.encode().unwrap());
        assert!(service.value("default", None, &store).is_err());
        record.profile = "default".into();
        record.revision = 0;
        *store.0.lock().unwrap() = Some(record.encode().unwrap());
        assert!(service.value("default", None, &store).is_err());
        record.revision = MAX_REVISION;
        *store.0.lock().unwrap() = Some(record.encode().unwrap());
        let maximum = store.load().unwrap();
        assert!(
            service
                .update(
                    "default",
                    &request(
                        MAX_REVISION,
                        Value::Null,
                        Value::Null,
                        json!({"mode":"direct"})
                    ),
                    &store
                )
                .is_err()
        );
        assert_eq!(store.load().unwrap(), maximum);
    }
}
