use super::*;
use crate::directory_notifications::parse_notification_buffer;

fn batch(records: &[(DirectoryAction, &str)]) -> NotificationBatch {
    let mut bytes = Vec::new();
    for (index, (action, name)) in records.iter().enumerate() {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let extent = super::super::HEADER_BYTES + utf16.len();
        let aligned = (extent + 3) & !3;
        let has_next = index + 1 != records.len();
        let next = if has_next { aligned as u32 } else { 0 };
        let action: u32 = match action {
            DirectoryAction::Added => 1,
            DirectoryAction::Removed => 2,
            DirectoryAction::Modified => 3,
            DirectoryAction::RenamedOldName => 4,
            DirectoryAction::RenamedNewName => 5,
        };
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.extend_from_slice(&action.to_le_bytes());
        bytes.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&utf16);
        if has_next {
            bytes.resize(bytes.len() + (aligned - extent), 0);
        }
    }
    parse_notification_buffer(&bytes)
}

fn pair_batch(records: &[(&str, &str)]) -> NotificationBatch {
    let mut names = Vec::with_capacity(records.len() * 2);
    for (old, new) in records {
        names.push((DirectoryAction::RenamedOldName, *old));
        names.push((DirectoryAction::RenamedNewName, *new));
    }
    batch(&names)
}

fn assert_rescan(batch: &NotificationBatch, expected: RenameHintReason) {
    assert_eq!(
        pair_rename_hints(batch),
        RenameHintBatch::RescanRequired(expected)
    );
}

#[test]
fn pairs_adjacent_same_parent_renames_and_allows_other_events_outside_pairs() {
    let batch = batch(&[
        (DirectoryAction::Added, "Personal\\before.txt"),
        (DirectoryAction::RenamedOldName, "Folder\\old.txt"),
        (DirectoryAction::RenamedNewName, "Folder\\new.txt"),
        (DirectoryAction::Modified, "Folder\\metadata.txt"),
        (DirectoryAction::RenamedOldName, "Folder\\second-old.txt"),
        (DirectoryAction::RenamedNewName, "Folder\\second-new.txt"),
        (DirectoryAction::Removed, "Personal\\after.txt"),
    ]);
    let RenameHintBatch::Pairs(pairs) = pair_rename_hints(&batch) else {
        panic!("expected same-batch pairs");
    };
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].old_components(), ["Folder", "old.txt"]);
    assert_eq!(pairs[0].new_components(), ["Folder", "new.txt"]);
    assert!(!format!("{pairs:?}").contains("old.txt"));
}

#[test]
fn orphan_interleaved_and_cross_parent_sequences_require_rescan() {
    for (records, reason) in [
        (
            vec![(DirectoryAction::RenamedNewName, "d\\new")],
            RenameHintReason::UnpairedNewName,
        ),
        (
            vec![(DirectoryAction::RenamedOldName, "d\\old")],
            RenameHintReason::UnpairedOldName,
        ),
        (
            vec![
                (DirectoryAction::RenamedOldName, "d\\old-a"),
                (DirectoryAction::RenamedOldName, "d\\old-b"),
            ],
            RenameHintReason::InterleavedRename,
        ),
        (
            vec![
                (DirectoryAction::RenamedOldName, "d\\old"),
                (DirectoryAction::Modified, "d\\middle"),
                (DirectoryAction::RenamedNewName, "d\\new"),
            ],
            RenameHintReason::InterleavedRename,
        ),
        (
            vec![
                (DirectoryAction::RenamedOldName, "d\\first-old"),
                (DirectoryAction::RenamedNewName, "d\\first-new"),
                (DirectoryAction::RenamedNewName, "d\\orphan-new"),
            ],
            RenameHintReason::UnpairedNewName,
        ),
        (
            vec![
                (DirectoryAction::RenamedOldName, "d\\old"),
                (DirectoryAction::RenamedNewName, "elsewhere\\new"),
            ],
            RenameHintReason::DifferentParent,
        ),
        (
            vec![
                (DirectoryAction::RenamedOldName, "Folder\\old"),
                (DirectoryAction::RenamedNewName, "folder\\new"),
            ],
            RenameHintReason::CaseAmbiguousEndpoint,
        ),
    ] {
        let parsed = batch(&records);
        assert_rescan(&parsed, reason);
    }
}

#[test]
fn overlapping_duplicate_chain_and_case_names_require_rescan() {
    for (records, reason) in [
        (
            vec![("d\\a", "d\\b"), ("d\\a", "d\\c")],
            RenameHintReason::DuplicateEndpoint,
        ),
        (
            vec![("d\\a", "d\\b"), ("d\\b", "d\\c")],
            RenameHintReason::RenameChain,
        ),
        (
            vec![("d\\a", "d\\b"), ("D\\A", "D\\c")],
            RenameHintReason::CaseAmbiguousEndpoint,
        ),
        (
            vec![("d\\a", "d\\b"), ("d\\B", "d\\c")],
            RenameHintReason::CaseAmbiguousEndpoint,
        ),
    ] {
        assert_rescan(&pair_batch(&records), reason);
    }
    assert_rescan(
        &pair_batch(&[("d\\same", "d\\SAME")]),
        RenameHintReason::CaseOnlyRename,
    );
    #[cfg(not(windows))]
    assert_rescan(
        &pair_batch(&[("d\\雪", "d\\star")]),
        RenameHintReason::UnsupportedName,
    );
    #[cfg(windows)]
    {
        let unicode = pair_batch(&[("d\\雪", "d\\star")]);
        assert!(
            matches!(pair_rename_hints(&unicode), RenameHintBatch::Pairs(pairs) if pairs.len() == 1)
        );
        assert_rescan(
            &pair_batch(&[("d\\Ä", "d\\ä")]),
            RenameHintReason::CaseOnlyRename,
        );
        assert_rescan(
            &pair_batch(&[("d\\Ä", "d\\one"), ("d\\ä", "d\\two")]),
            RenameHintReason::CaseAmbiguousEndpoint,
        );
    }
}

#[test]
fn upstream_rescan_is_propagated_and_no_pair_state_crosses_batches() {
    let upstream = NotificationBatch::RescanRequired(RescanReason::RootChanged);
    assert_rescan(
        &upstream,
        RenameHintReason::SourceRescan(RescanReason::RootChanged),
    );

    let old = batch(&[(DirectoryAction::RenamedOldName, "d\\old")]);
    let new = batch(&[(DirectoryAction::RenamedNewName, "d\\new")]);
    assert_rescan(&old, RenameHintReason::UnpairedOldName);
    assert_rescan(&new, RenameHintReason::UnpairedNewName);
    assert_rescan(
        &NotificationBatch::Hints(Vec::new()),
        RenameHintReason::SourceRescan(RescanReason::EmptyCompletion),
    );
}

#[test]
fn caller_constructed_batches_are_bounded_by_count_and_bytes() {
    let single = batch(&[(DirectoryAction::Added, "d\\x")]);
    let NotificationBatch::Hints(hints) = single else {
        panic!("expected parsed hint");
    };
    let oversized = NotificationBatch::Hints(vec![
        hints[0].clone();
        crate::directory_notifications::MAX_NOTIFICATION_HINTS
            + 1
    ]);
    assert_rescan(&oversized, RenameHintReason::Limit);

    let long_component = "x".repeat(255);
    let long = batch(&[(DirectoryAction::Added, &long_component)]);
    let NotificationBatch::Hints(hints) = long else {
        panic!("expected one bounded long component");
    };
    let repeated = NotificationBatch::Hints(vec![hints[0].clone(); 130]);
    assert_rescan(&repeated, RenameHintReason::Limit);
}

#[test]
fn output_pair_count_cannot_exceed_half_the_input_bound() {
    let records: Vec<_> = (0..crate::directory_notifications::MAX_NOTIFICATION_HINTS / 2)
        .map(|index| {
            let old = format!("Personal\\old-{index}.txt");
            let new = format!("Personal\\new-{index}.txt");
            (old, new)
        })
        .collect();
    let mut notifications = Vec::with_capacity(records.len() * 2);
    for (old, new) in &records {
        notifications.push((DirectoryAction::RenamedOldName, old.as_str()));
        notifications.push((DirectoryAction::RenamedNewName, new.as_str()));
    }
    let parsed = batch(&notifications);
    let RenameHintBatch::Pairs(pairs) = pair_rename_hints(&parsed) else {
        panic!("expected maximum bounded pair set");
    };
    assert_eq!(
        pairs.len(),
        crate::directory_notifications::MAX_NOTIFICATION_HINTS / 2
    );
}
