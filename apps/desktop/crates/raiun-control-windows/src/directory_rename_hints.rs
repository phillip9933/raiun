//! Conservative pairing of adjacent rename names within one notification batch.
//!
//! The output is only a borrowed name hint. It grants no object identity,
//! ancestry, remote identity, or mutation authority. A consumer must rescan
//! whenever pairing is ambiguous or incomplete.

use super::{
    DirectoryAction, DirectoryHint, MAX_COMPONENTS, MAX_NOTIFICATION_HINTS,
    NOTIFICATION_BUFFER_BYTES, NotificationBatch, RescanReason,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameHintReason {
    SourceRescan(RescanReason),
    Limit,
    UnpairedOldName,
    UnpairedNewName,
    InterleavedRename,
    DifferentParent,
    UnsupportedName,
    CaseOnlyRename,
    DuplicateEndpoint,
    RenameChain,
    CaseAmbiguousEndpoint,
}

/// One adjacent old/new pair. Components borrow the source batch and remain
/// explicitly untrusted relative names.
#[derive(Clone, Eq, PartialEq)]
pub struct RenameHintPair<'a> {
    old_components: &'a [String],
    new_components: &'a [String],
}

impl RenameHintPair<'_> {
    pub fn old_components(&self) -> &[String] {
        self.old_components
    }

    pub fn new_components(&self) -> &[String] {
        self.new_components
    }
}

impl fmt::Debug for RenameHintPair<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenameHintPair")
            .field("old_components", &"[UNTRUSTED RELATIVE HINT]")
            .field("new_components", &"[UNTRUSTED RELATIVE HINT]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenameHintBatch<'a> {
    Pairs(Vec<RenameHintPair<'a>>),
    RescanRequired(RenameHintReason),
}

/// Pair adjacent `RenamedOldName` then `RenamedNewName` hints from exactly one
/// already-parsed batch. Windows compares Unicode endpoints with its ordinal
/// case table. Other hosts retain the ASCII-only fallback. Any ambiguity or
/// incomplete pair invalidates the whole set.
pub fn pair_rename_hints(batch: &NotificationBatch) -> RenameHintBatch<'_> {
    pair_hints(batch, false)
}
/// Opt-in adjacent cross-parent pairs for consumers that independently prove
/// both parents, original FileID and same account/Space/root. Hints still grant
/// no MOVE or object authority; all original bounds/alias fences remain.
pub fn pair_move_hints(batch: &NotificationBatch) -> RenameHintBatch<'_> {
    pair_hints(batch, true)
}
fn pair_hints(batch: &NotificationBatch, cross_parent: bool) -> RenameHintBatch<'_> {
    let hints = match batch {
        NotificationBatch::RescanRequired(reason) => {
            return RenameHintBatch::RescanRequired(RenameHintReason::SourceRescan(*reason));
        }
        NotificationBatch::Hints(hints) => hints,
    };
    if hints.is_empty() {
        return RenameHintBatch::RescanRequired(RenameHintReason::SourceRescan(
            RescanReason::EmptyCompletion,
        ));
    }
    if hints.len() > MAX_NOTIFICATION_HINTS || !bounded_batch_size(hints) {
        return RenameHintBatch::RescanRequired(RenameHintReason::Limit);
    }

    let mut pairs = Vec::with_capacity(hints.len().min(MAX_NOTIFICATION_HINTS) / 2);
    let mut pending_old: Option<&DirectoryHint> = None;
    for hint in hints {
        match hint.action() {
            DirectoryAction::RenamedOldName => {
                if pending_old.is_some() {
                    return RenameHintBatch::RescanRequired(RenameHintReason::InterleavedRename);
                }
                pending_old = Some(hint);
            }
            DirectoryAction::RenamedNewName => {
                let Some(old) = pending_old.take() else {
                    return RenameHintBatch::RescanRequired(RenameHintReason::UnpairedNewName);
                };
                let old_components = old.components();
                let new_components = hint.components();
                #[cfg(not(windows))]
                if old_components
                    .iter()
                    .chain(new_components)
                    .any(|component| !component.is_ascii())
                {
                    return RenameHintBatch::RescanRequired(RenameHintReason::UnsupportedName);
                }
                if !same_parent(old_components, new_components)
                    && (!cross_parent
                        || same_parent_case_insensitive(old_components, new_components))
                {
                    let reason = if same_parent_case_insensitive(old_components, new_components) {
                        RenameHintReason::CaseAmbiguousEndpoint
                    } else {
                        RenameHintReason::DifferentParent
                    };
                    return RenameHintBatch::RescanRequired(reason);
                }
                if same_parent(old_components, new_components)
                    && old_components
                        .last()
                        .zip(new_components.last())
                        .is_some_and(|(old_name, new_name)| names_may_alias(old_name, new_name))
                {
                    return RenameHintBatch::RescanRequired(RenameHintReason::CaseOnlyRename);
                }
                let candidate = RenameHintPair {
                    old_components,
                    new_components,
                };
                if pairs.len() >= MAX_NOTIFICATION_HINTS / 2 {
                    return RenameHintBatch::RescanRequired(RenameHintReason::Limit);
                }
                if let Some(reason) = pairs
                    .iter()
                    .find_map(|previous| endpoint_conflict(previous, &candidate))
                {
                    return RenameHintBatch::RescanRequired(reason);
                }
                pairs.push(candidate);
            }
            _ if pending_old.is_some() => {
                return RenameHintBatch::RescanRequired(RenameHintReason::InterleavedRename);
            }
            _ => {}
        }
    }
    if pending_old.is_some() {
        return RenameHintBatch::RescanRequired(RenameHintReason::UnpairedOldName);
    }
    RenameHintBatch::Pairs(pairs)
}

fn bounded_batch_size(hints: &[DirectoryHint]) -> bool {
    let mut bytes = 0usize;
    for hint in hints {
        let components = hint.components();
        if components.is_empty() || components.len() > MAX_COMPONENTS {
            return false;
        }
        let mut name_units = components.len().saturating_sub(1);
        for component in components {
            let units = component.encode_utf16().count();
            if units == 0 || units > 255 {
                return false;
            }
            let Some(total) = name_units.checked_add(units) else {
                return false;
            };
            name_units = total;
        }
        let Some(record_bytes) = name_units
            .checked_mul(2)
            .and_then(|length| length.checked_add(super::HEADER_BYTES))
        else {
            return false;
        };
        let Some(aligned_record_bytes) = record_bytes.checked_add(3).map(|value| value & !3) else {
            return false;
        };
        let Some(total) = bytes.checked_add(aligned_record_bytes) else {
            return false;
        };
        bytes = total;
        if bytes > NOTIFICATION_BUFFER_BYTES {
            return false;
        }
    }
    true
}

// Pairing remains hint-only. A failed OS comparison is treated as a possible
// alias, so it can only refuse a pair rather than admit a conflicting endpoint.
fn names_may_alias(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    #[cfg(windows)]
    {
        super::native::ordinal_names_equal(left, right).unwrap_or(true)
    }
    #[cfg(not(windows))]
    {
        left.eq_ignore_ascii_case(right)
    }
}

fn same_parent(old: &[String], new: &[String]) -> bool {
    if old.is_empty() || new.is_empty() || old.len() != new.len() {
        return false;
    }
    old[..old.len() - 1]
        .iter()
        .zip(&new[..new.len() - 1])
        .all(|(old, new)| old == new)
}

fn same_parent_case_insensitive(old: &[String], new: &[String]) -> bool {
    if old.is_empty() || new.is_empty() || old.len() != new.len() {
        return false;
    }
    old[..old.len() - 1]
        .iter()
        .zip(&new[..new.len() - 1])
        .all(|(old, new)| names_may_alias(old, new))
}

fn endpoint_relation(left: &[String], right: &[String]) -> EndpointRelation {
    if left.len() != right.len()
        || !left
            .iter()
            .zip(right)
            .all(|(left, right)| names_may_alias(left, right))
    {
        EndpointRelation::Different
    } else if left.iter().zip(right).all(|(left, right)| left == right) {
        EndpointRelation::Exact
    } else {
        EndpointRelation::CaseAmbiguous
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EndpointRelation {
    Different,
    Exact,
    CaseAmbiguous,
}

fn endpoint_conflict(
    previous: &RenameHintPair<'_>,
    candidate: &RenameHintPair<'_>,
) -> Option<RenameHintReason> {
    let relations = [
        (
            endpoint_relation(previous.old_components, candidate.old_components),
            false,
        ),
        (
            endpoint_relation(previous.new_components, candidate.new_components),
            false,
        ),
        (
            endpoint_relation(previous.new_components, candidate.old_components),
            true,
        ),
        (
            endpoint_relation(previous.old_components, candidate.new_components),
            true,
        ),
    ];
    if relations
        .iter()
        .any(|(relation, _)| *relation == EndpointRelation::CaseAmbiguous)
    {
        Some(RenameHintReason::CaseAmbiguousEndpoint)
    } else if relations
        .iter()
        .any(|(relation, _)| *relation == EndpointRelation::Exact)
    {
        if relations
            .iter()
            .any(|(relation, is_chain)| *relation == EndpointRelation::Exact && *is_chain)
        {
            Some(RenameHintReason::RenameChain)
        } else {
            Some(RenameHintReason::DuplicateEndpoint)
        }
    } else {
        None
    }
}

#[cfg(test)]
#[path = "directory_rename_hints_tests.rs"]
mod tests;
