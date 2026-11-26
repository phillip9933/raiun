//! One quota-held v2 metadata query's decoded-byte reuse. Callers still read,
//! charge and verify every current immutable file before invoking `open`.
use crate::{EditRecordProtector, JournalError};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

// Retained payload capacities plus the explicit per-entry/key/bucket charge.
// Map allocation overhead is additionally bounded by MAX_ENTRIES; this is not
// a claim about the complete process's memory use.
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

struct Entry {
    aad: Zeroizing<Vec<u8>>,
    sealed: Zeroizing<Vec<u8>>,
    plain: Zeroizing<Vec<u8>>,
}
impl Entry {
    fn matches(&self, aad: &[u8], sealed: &[u8]) -> bool {
        self.aad.as_slice() == aad && self.sealed.as_slice() == sealed
    }
    fn charge(&self) -> Option<usize> {
        metadata_charge(
            self.aad.capacity(),
            self.sealed.capacity(),
            self.plain.capacity(),
        )
    }
}
fn metadata_charge(aad: usize, sealed: usize, plain: usize) -> Option<usize> {
    aad.checked_add(sealed)?
        .checked_add(plain)?
        .checked_add(std::mem::size_of::<Entry>())?
        .checked_add(std::mem::size_of::<[u8; 32]>())?
        .checked_add(std::mem::size_of::<Vec<Entry>>())
}
#[derive(Default)]
struct Memo {
    buckets: HashMap<[u8; 32], Vec<Entry>>,
    entries: usize,
    bytes: usize,
}

pub(super) struct MetadataOpenMemo {
    original: Arc<dyn EditRecordProtector>,
    memo: Mutex<Memo>,
}
impl MetadataOpenMemo {
    /// Create only inside ONE existing-quota fresh-create metadata query. No
    /// returned summary/key retains this adapter or its zeroized decoded bytes.
    pub(super) fn scoped(original: Arc<dyn EditRecordProtector>) -> Arc<dyn EditRecordProtector> {
        Arc::new(Self {
            original,
            memo: Mutex::new(Memo::default()),
        })
    }
}

fn lookup_digest(aad: &[u8], sealed: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"raiun/v2/fresh-query/metadata-open-memo/v1\0");
    digest.update((aad.len() as u64).to_le_bytes());
    digest.update(aad);
    digest.update((sealed.len() as u64).to_le_bytes());
    digest.update(sealed);
    digest.finalize().into()
}

impl EditRecordProtector for MetadataOpenMemo {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, JournalError> {
        self.original.seal(aad, plain)
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
        let digest = lookup_digest(aad, sealed);
        {
            let memo = self
                .memo
                .lock()
                .map_err(|_| JournalError::ProtectionFailed)?;
            if let Some(entry) = memo
                .buckets
                .get(&digest)
                .and_then(|bucket| bucket.iter().find(|entry| entry.matches(aad, sealed)))
            {
                // A digest chooses candidates only. Fresh ciphertext AND AAD
                // must match exactly; no path, FileID or commitment is authority.
                return Ok(entry.plain.to_vec());
            }
        }
        // Cache only successful original authentication. Neither crypto nor
        // file IO runs under the memo lock, and errors are never remembered.
        let plain = Zeroizing::new(self.original.open(aad, sealed)?);
        let mut memo = self
            .memo
            .lock()
            .map_err(|_| JournalError::ProtectionFailed)?;
        if memo.entries >= MAX_ENTRIES
            || memo
                .buckets
                .get(&digest)
                .is_some_and(|bucket| bucket.iter().any(|entry| entry.matches(aad, sealed)))
        {
            return Ok(plain.to_vec());
        }
        if metadata_charge(aad.len(), sealed.len(), plain.capacity())
            .and_then(|charge| memo.bytes.checked_add(charge))
            .is_none_or(|next_bytes| next_bytes > MAX_BYTES)
        {
            // Avoid copying large AAD/ciphertext when this invocation's cache
            // has no remaining space. Authentication has already succeeded.
            return Ok(plain.to_vec());
        }
        let entry = Entry {
            aad: Zeroizing::new(aad.to_vec()),
            sealed: Zeroizing::new(sealed.to_vec()),
            plain,
        };
        let Some(next_bytes) = entry
            .charge()
            .and_then(|charge| memo.bytes.checked_add(charge))
        else {
            return Ok(entry.plain.to_vec());
        };
        if next_bytes > MAX_BYTES {
            // Capacity is scheduling/storage only: decode normally, without
            // eviction, relaxed validation or a new metadata-work allowance.
            return Ok(entry.plain.to_vec());
        }
        let result = entry.plain.to_vec();
        memo.buckets.entry(digest).or_default().push(entry);
        memo.entries += 1;
        memo.bytes = next_bytes;
        Ok(result)
    }
    fn protect_directory(&self, path: &Path) -> Result<(), JournalError> {
        self.original.protect_directory(path)
    }
}
