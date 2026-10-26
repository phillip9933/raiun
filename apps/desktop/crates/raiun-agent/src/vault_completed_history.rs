//! Immutable, content-addressed batches of completed vault edit history.
//! Reachability is granted only by a protected child-index tip.
use super::super::vault_edit_disposition::DispositionRow;
use super::{CaptureRef, MAX_BYTES, MAX_CAPTURE_REFS, Scope, UploadAttemptRow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use zeroize::Zeroizing;

const VERSION: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegmentRef {
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletedRow {
    pub(crate) capture: CaptureRef,
    pub(crate) attempt: UploadAttemptRow,
    pub(crate) disposition: DispositionRow,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Segment {
    version: u32,
    scope: Scope,
    previous: Option<SegmentRef>,
    rows: Vec<CompletedRow>,
}

struct Bounded(Zeroizing<Vec<u8>>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len > MAX_BYTES)
        {
            return Err(io::Error::other("completed history segment bounds"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Segment {
    pub(crate) fn new(scope: Scope, previous: Option<SegmentRef>, rows: Vec<CompletedRow>) -> Self {
        Self {
            version: VERSION,
            scope,
            previous,
            rows,
        }
    }
    pub(crate) fn previous(&self) -> Option<SegmentRef> {
        self.previous
    }
    pub(crate) fn rows(&self) -> &[CompletedRow] {
        &self.rows
    }
    pub(crate) fn encode(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut out = Bounded(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut out, self).map_err(|_| io::Error::other("segment encode"))?;
        Ok(out.0)
    }
    pub(crate) fn decode(bytes: &[u8], scope: &Scope) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(io::Error::other("segment size"));
        }
        let segment: Self =
            serde_json::from_slice(bytes).map_err(|_| io::Error::other("segment schema"))?;
        if segment.version != VERSION
            || &segment.scope != scope
            || segment.rows.is_empty()
            || segment.rows.len() > MAX_CAPTURE_REFS
        {
            return Err(io::Error::other("segment binding or bounds"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in &segment.rows {
            if !ids.insert(row.capture.id())
                || row.attempt.capture_id != row.capture.id()
                || row.disposition.reference() != &row.capture
                || !row.disposition.is_native_completed()
            {
                return Err(io::Error::other("segment row binding"));
            }
        }
        Ok(segment)
    }
}

/// Plan the complete immutable chain before any store write. Segment envelopes
/// can be larger than the equivalent active-index arrays; each maximal prefix
/// therefore observes the same byte bound independently.
pub(super) struct EncodedSegment {
    pub(super) reference: SegmentRef,
    pub(super) bytes: Zeroizing<Vec<u8>>,
}
pub(super) fn encode_bounded_chain(
    scope: &Scope,
    mut previous: Option<SegmentRef>,
    rows: &[CompletedRow],
) -> io::Result<Vec<EncodedSegment>> {
    if rows.is_empty() || rows.len() > MAX_CAPTURE_REFS {
        return Err(io::Error::other("completed history batch bounds"));
    }
    let mut planned = Vec::new();
    let mut offset = 0;
    while offset < rows.len() {
        let remaining = rows.len() - offset;
        let encode_prefix = |len| {
            Segment::new(scope.clone(), previous, rows[offset..offset + len].to_vec()).encode()
        };
        let (count, bytes) = if let Ok(bytes) = encode_prefix(remaining) {
            (remaining, bytes)
        } else {
            let (mut low, mut high) = (1, remaining - 1);
            let mut best = None;
            while low <= high {
                let count = low + (high - low) / 2;
                if let Ok(bytes) = encode_prefix(count) {
                    best = Some((count, bytes));
                    low = count + 1;
                } else {
                    high = count - 1;
                }
            }
            best.ok_or_else(|| io::Error::other("completed history row exceeds bound"))?
        };
        let reference = SegmentRef {
            digest: Sha256::digest(bytes.as_slice()).into(),
        };
        planned.push(EncodedSegment { reference, bytes });
        previous = Some(reference);
        offset += count;
    }
    Ok(planned)
}
