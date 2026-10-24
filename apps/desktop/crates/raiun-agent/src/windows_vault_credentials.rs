//! Remembered-password custody only. No unlocked-session or remote authority.
//! Caller supplies verified scopes and fences metadata/integrity/session lifecycle.
use raiun_engine::folder_pairs::AccountScope;
use raiun_vault::session::VaultSessionScope;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 128;
const MAX_KEY: usize = 16 * 1024;
const MAGIC: &[u8] = b"RAIUN-VAULT-CREDENTIALS\0\x01";
fn refused() -> String {
    "Remembered vault credentials are unavailable or changed".into()
}
type Result<T> = std::result::Result<T, String>;

// Nonsecret canonical scope fields. Passwords are never passed to serde.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFields {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    profile: String,
    key: Vec<u8>,
}
impl Scope {
    pub(super) fn new(
        profile: &str,
        server: &str,
        client: &str,
        issuer: Option<&str>,
        subject: &str,
        vault: &VaultSessionScope,
    ) -> Result<Self> {
        let account = AccountFields {
            profile: profile.into(),
            server: server.into(),
            client: client.into(),
            issuer: issuer.map(str::to_owned),
            subject: subject.into(),
        };
        Self::validated(
            account,
            [
                vault.account_id().into(),
                vault.server_origin().into(),
                vault.space_id().into(),
                vault.resource_id().into(),
            ],
        )
    }
    // The caller obtains these bytes only from its already-verified runtime
    // account, never a registration record or incoming request.
    pub(super) fn from_trusted_account(
        profile: &str,
        account: &[u8],
        vault: &VaultSessionScope,
    ) -> Result<Self> {
        let a: AccountFields = serde_json::from_slice(account).map_err(|_| refused())?;
        if a.profile != profile {
            return Err(refused());
        }
        Self::validated(
            a,
            [
                vault.account_id().into(),
                vault.server_origin().into(),
                vault.space_id().into(),
                vault.resource_id().into(),
            ],
        )
    }
    fn validated(a: AccountFields, v: [String; 4]) -> Result<Self> {
        if !valid_profile(&a.profile) {
            return Err(refused());
        }
        let model = AccountScope::new(
            a.profile.clone(),
            a.server.clone(),
            a.client,
            a.issuer,
            a.subject,
        )
        .map_err(|_| refused())?;
        let vault = VaultSessionScope::new(&v[0], &v[1], &v[2], &v[3]).map_err(|_| refused())?;
        let origin = url::Url::parse(&a.server)
            .map_err(|_| refused())?
            .origin()
            .ascii_serialization();
        if a.profile != vault.account_id()
            || origin != vault.server_origin()
            || v[1] != vault.server_origin()
        {
            return Err(refused());
        }
        let key = serde_json::to_vec(&(model, v)).map_err(|_| refused())?;
        if key.len() > MAX_KEY {
            return Err(refused());
        }
        Ok(Self {
            profile: a.profile,
            key,
        })
    }
    fn decode(key: &[u8]) -> Result<Self> {
        if key.is_empty() || key.len() > MAX_KEY {
            return Err(refused());
        }
        let (a, v): (AccountFields, [String; 4]) =
            serde_json::from_slice(key).map_err(|_| refused())?;
        let scope = Self::validated(a, v)?;
        if scope.key != key {
            return Err(refused());
        }
        Ok(scope)
    }
}
fn valid_profile(p: &str) -> bool {
    p == "default"
        || (p.len() == 40
            && p.starts_with("profile-")
            && p[8..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

pub(super) trait Store {
    fn load(&self, profile: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn compare_exchange(&self, profile: &str, expected: Option<&[u8]>, next: &[u8]) -> Result<()>;
}
// Existing trusted Agent adapter; no real store is constructed by this module.
#[cfg(windows)]
impl Store for super::DpapiStore {
    fn load(&self, profile: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.check_scope(profile)?;
        self.store
            .load_vault_credentials(profile)
            .map_err(|_| refused())
    }
    fn compare_exchange(&self, profile: &str, expected: Option<&[u8]>, next: &[u8]) -> Result<()> {
        self.check_scope(profile)?;
        self.store
            .compare_exchange_vault_credentials(profile, expected, next)
            .map_err(|_| refused())
    }
}

/// Single-use captured authority. No secret, Debug, Clone or serialization.
pub(super) struct RememberTicket {
    scope: Scope,
    profile_epoch: [u8; 32],
    vault_epoch: [u8; 32],
}
struct Row {
    scope: Scope,
    epoch: [u8; 32],
    password: Zeroizing<Vec<u8>>,
}
struct Document {
    profile: String,
    epoch: [u8; 32],
    rows: Vec<Row>,
}
fn generation() -> Result<[u8; 32]> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| refused())?;
    if b == [0; 32] {
        return Err(refused());
    }
    Ok(b)
}
fn password_valid(p: &[u8]) -> bool {
    !p.is_empty() && p.len() <= 4096 && std::str::from_utf8(p).is_ok()
}
fn secret_copy(p: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(p.len()));
    out.extend_from_slice(p);
    out
}
impl Document {
    fn fresh(profile: &str) -> Result<Self> {
        if !valid_profile(profile) {
            return Err(refused());
        }
        Ok(Self {
            profile: profile.into(),
            epoch: generation()?,
            rows: vec![],
        })
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if !valid_profile(&self.profile) || self.epoch == [0; 32] || self.rows.len() > MAX_ROWS {
            return Err(refused());
        }
        let mut total = MAGIC.len() + 2 + self.profile.len() + 32 + 2;
        for (i, row) in self.rows.iter().enumerate() {
            if row.scope.profile != self.profile
                || row.epoch == [0; 32]
                || (!row.password.is_empty() && !password_valid(&row.password))
                || self.rows[..i].iter().any(|r| r.scope == row.scope)
            {
                return Err(refused());
            }
            total = total
                .checked_add(4 + row.scope.key.len() + 32 + 2 + row.password.len())
                .ok_or_else(refused)?;
        }
        if total > MAX_BYTES {
            return Err(refused());
        }
        // Final exact capacity is reserved BEFORE any secret is copied.
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.profile.len() as u16).to_le_bytes());
        out.extend_from_slice(self.profile.as_bytes());
        out.extend_from_slice(&self.epoch);
        out.extend_from_slice(&(self.rows.len() as u16).to_le_bytes());
        for row in &self.rows {
            out.extend_from_slice(&(row.scope.key.len() as u32).to_le_bytes());
            out.extend_from_slice(&row.scope.key);
            out.extend_from_slice(&row.epoch);
            out.extend_from_slice(&(row.password.len() as u16).to_le_bytes());
            out.extend_from_slice(&row.password);
        }
        Ok(out)
    }
    fn decode(bytes: &[u8], profile: &str) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(refused());
        }
        let mut c = Cursor(bytes);
        if c.take(MAGIC.len())? != MAGIC {
            return Err(refused());
        }
        let n = c.u16()?;
        let actual = std::str::from_utf8(c.take(n)?).map_err(|_| refused())?;
        if actual != profile || !valid_profile(actual) {
            return Err(refused());
        }
        let epoch = c.take(32)?.try_into().map_err(|_| refused())?;
        if epoch == [0; 32] {
            return Err(refused());
        }
        let count = c.u16()?;
        if count > MAX_ROWS {
            return Err(refused());
        }
        let mut rows: Vec<Row> = Vec::with_capacity(count);
        for _ in 0..count {
            let key_len = c.u32()?;
            if key_len > MAX_KEY {
                return Err(refused());
            }
            let scope = Scope::decode(c.take(key_len)?)?;
            let row_epoch = c.take(32)?.try_into().map_err(|_| refused())?;
            let n = c.u16()?;
            if n > 4096 {
                return Err(refused());
            }
            let p = c.take(n)?;
            if scope.profile != profile
                || row_epoch == [0; 32]
                || (!p.is_empty() && !password_valid(p))
                || rows.iter().any(|r| r.scope == scope)
            {
                return Err(refused());
            }
            rows.push(Row {
                scope,
                epoch: row_epoch,
                password: secret_copy(p),
            });
        }
        if !c.0.is_empty() {
            return Err(refused());
        }
        Ok(Self {
            profile: profile.into(),
            epoch,
            rows,
        })
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(refused());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| refused())?) as usize)
    }
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| refused())?) as usize)
    }
}
type LoadedDocument = (Option<Zeroizing<Vec<u8>>>, Option<Document>);
fn existing(store: &dyn Store, profile: &str) -> Result<LoadedDocument> {
    if !valid_profile(profile) {
        return Err(refused());
    }
    let bytes = store.load(profile)?;
    let doc = bytes
        .as_ref()
        .map(|b| Document::decode(b, profile))
        .transpose()?;
    Ok((bytes, doc))
}
pub(super) fn begin_remember(store: &dyn Store, scope: Scope) -> Result<RememberTicket> {
    let (old, doc) = existing(store, &scope.profile)?;
    let mut doc = match doc {
        Some(d) => d,
        None => Document::fresh(&scope.profile)?,
    };
    let epoch = generation()?;
    if let Some(row) = doc.rows.iter_mut().find(|r| r.scope == scope) {
        row.epoch = epoch;
    } else {
        if doc.rows.len() >= MAX_ROWS {
            return Err(refused());
        }
        doc.rows.push(Row {
            scope: scope.clone(),
            epoch,
            password: Zeroizing::new(vec![]),
        });
    }
    let next = doc.encode()?;
    store.compare_exchange(&scope.profile, old.as_ref().map(|b| b.as_slice()), &next)?;
    Ok(RememberTicket {
        scope,
        profile_epoch: doc.epoch,
        vault_epoch: epoch,
    })
}
pub(super) fn commit_remember(
    store: &dyn Store,
    ticket: RememberTicket,
    password: &[u8],
) -> Result<()> {
    if !password_valid(password) {
        return Err(refused());
    }
    let (old, doc) = existing(store, &ticket.scope.profile)?;
    let mut doc = doc.ok_or_else(refused)?;
    if doc.epoch != ticket.profile_epoch {
        return Err(refused());
    }
    let row = doc
        .rows
        .iter_mut()
        .find(|r| r.scope == ticket.scope && r.epoch == ticket.vault_epoch)
        .ok_or_else(refused)?;
    row.password = secret_copy(password);
    let next = doc.encode()?;
    store.compare_exchange(
        &ticket.scope.profile,
        old.as_ref().map(|b| b.as_slice()),
        &next,
    )
}
pub(super) fn load(store: &dyn Store, scope: &Scope) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let (_, doc) = existing(store, &scope.profile)?;
    Ok(doc
        .and_then(|d| d.rows.into_iter().find(|r| r.scope == *scope))
        .and_then(|r| {
            if r.password.is_empty() {
                None
            } else {
                Some(r.password)
            }
        }))
}
pub(super) fn forget(store: &dyn Store, scope: &Scope) -> Result<()> {
    let (old, doc) = existing(store, &scope.profile)?;
    let mut doc = match doc {
        Some(doc) => doc,
        None => Document::fresh(&scope.profile)?,
    };
    if let Some(row) = doc.rows.iter_mut().find(|r| r.scope == *scope) {
        row.epoch = generation()?;
        row.password = Zeroizing::new(vec![]);
    } else {
        if doc.rows.len() >= MAX_ROWS {
            return Err(refused());
        }
        doc.rows.push(Row {
            scope: scope.clone(),
            epoch: generation()?,
            password: Zeroizing::new(vec![]),
        });
    }
    let next = doc.encode()?;
    store.compare_exchange(&scope.profile, old.as_ref().map(|b| b.as_slice()), &next)
}
pub(super) fn revoke_profile(store: &dyn Store, profile: &str) -> Result<()> {
    let (old, doc) = existing(store, profile)?;
    let mut doc = match doc {
        Some(doc) => doc,
        None => Document::fresh(profile)?,
    };
    doc.epoch = generation()?;
    doc.rows.clear();
    let next = doc.encode()?;
    store.compare_exchange(profile, old.as_ref().map(|b| b.as_slice()), &next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
    impl Store for Memory {
        fn load(&self, p: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.lock().unwrap().get(p).map(|v| secret_copy(v)))
        }
        fn compare_exchange(&self, p: &str, old: Option<&[u8]>, next: &[u8]) -> Result<()> {
            let mut m = self.0.lock().unwrap();
            if m.get(p).map(|v| v.as_slice()) != old {
                return Err(refused());
            }
            m.insert(p.into(), secret_copy(next));
            Ok(())
        }
    }
    fn scope(subject: &str, root: &str) -> Scope {
        Scope::new(
            "default",
            "https://cloud.example/",
            "client",
            Some("https://issuer.example/"),
            subject,
            &VaultSessionScope::new("default", "https://cloud.example", "space", root).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn exact_scope_roundtrip_and_missing_reads_do_not_create_authority() {
        let store = Memory::default();
        let a = scope("a", "root");
        assert!(load(&store, &a).unwrap().is_none());
        assert!(store.0.lock().unwrap().is_empty());
        let password = "  synthetic-🔒  ".as_bytes();
        commit_remember(&store, begin_remember(&store, a.clone()).unwrap(), password).unwrap();
        assert_eq!(load(&store, &a).unwrap().unwrap().as_slice(), password);
        assert!(load(&store, &scope("b", "root")).unwrap().is_none());
        assert!(load(&store, &scope("a", "other-root")).unwrap().is_none());
        let bytes = store.load("default").unwrap().unwrap();
        let reopened = Memory::default();
        reopened.compare_exchange("default", None, &bytes).unwrap();
        assert_eq!(load(&reopened, &a).unwrap().unwrap().as_slice(), password);
        let wrong = VaultSessionScope::new(
            "profile-11111111111111111111111111111111",
            "https://cloud.example",
            "space",
            "root",
        )
        .unwrap();
        assert!(
            Scope::new(
                "default",
                "https://cloud.example/",
                "client",
                None,
                "a",
                &wrong
            )
            .is_err()
        );
    }
    #[test]
    fn forget_logout_and_new_remember_revoke_stale_tickets() {
        let store = Memory::default();
        let a = scope("a", "root");
        // Missing authority and missing row must still publish a revocation
        // tombstone, fencing a concurrent begin's previously-read CAS value.
        forget(&store, &a).unwrap();
        let tombstone = store.load("default").unwrap().unwrap();
        assert!(store.compare_exchange("default", None, &tombstone).is_err());
        let other = scope("a", "other");
        forget(&store, &other).unwrap();
        assert!(
            store
                .compare_exchange("default", Some(&tombstone), &tombstone)
                .is_err()
        );
        let stale = begin_remember(&store, a.clone()).unwrap();
        forget(&store, &a).unwrap();
        assert!(commit_remember(&store, stale, b"old").is_err());
        let stale = begin_remember(&store, a.clone()).unwrap();
        let current = begin_remember(&store, a.clone()).unwrap();
        assert!(commit_remember(&store, stale, b"old").is_err());
        commit_remember(&store, current, b"current").unwrap();
        let stale = begin_remember(&store, a.clone()).unwrap();
        revoke_profile(&store, "default").unwrap();
        assert!(commit_remember(&store, stale, b"old").is_err());
        assert!(load(&store, &a).unwrap().is_none());
        commit_remember(&store, begin_remember(&store, a.clone()).unwrap(), b"new").unwrap();
        assert_eq!(load(&store, &a).unwrap().unwrap().as_slice(), b"new");
        // A stale full-byte writer cannot roll a revoked document back.
        let old = store.load("default").unwrap().unwrap();
        revoke_profile(&store, "default").unwrap();
        assert!(store.compare_exchange("default", Some(&old), &old).is_err());
    }
    #[test]
    fn corruption_and_bounds_refuse_without_resetting_previous_document() {
        let store = Memory::default();
        let a = scope("a", "root");
        commit_remember(&store, begin_remember(&store, a.clone()).unwrap(), b"saved").unwrap();
        let old = store.load("default").unwrap().unwrap();
        let ticket = begin_remember(&store, a.clone()).unwrap();
        let before = store.load("default").unwrap().unwrap();
        assert!(commit_remember(&store, ticket, &vec![b'x'; 4097]).is_err());
        assert!(store.load("default").unwrap().unwrap().as_slice() == before.as_slice());
        let mut malformed = secret_copy(&old);
        malformed.push(0);
        store
            .compare_exchange("default", Some(&before), &malformed)
            .unwrap();
        assert!(load(&store, &a).is_err());
        assert!(begin_remember(&store, a.clone()).is_err());
        assert!(revoke_profile(&store, "default").is_err());
        assert!(store.load("default").unwrap().unwrap().as_slice() == malformed.as_slice());
        let mut doc = Document::fresh("default").unwrap();
        for i in 0..MAX_ROWS {
            doc.rows.push(Row {
                scope: scope("a", &format!("root-{i}")),
                epoch: [1; 32],
                password: secret_copy(b"synthetic"),
            });
        }
        let bytes = doc.encode().unwrap();
        let bounded = Memory::default();
        bounded.compare_exchange("default", None, &bytes).unwrap();
        assert!(begin_remember(&bounded, a).is_err());
        assert!(bounded.load("default").unwrap().unwrap().as_slice() == bytes.as_slice());
        assert!(Document::decode(&vec![0; MAX_BYTES + 1], "default").is_err());
    }
}
