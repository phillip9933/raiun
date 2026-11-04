use super::*;

fn record(action: u32, name: &str, next: bool) -> Vec<u8> {
    let name: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let length = HEADER_BYTES + name.len();
    let aligned = (length + 3) & !3;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(if next { aligned as u32 } else { 0 }).to_le_bytes());
    bytes.extend_from_slice(&action.to_le_bytes());
    bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&name);
    if next {
        bytes.resize(aligned, 0);
    }
    bytes
}
fn rejected(bytes: &[u8]) {
    assert!(matches!(
        parse_notification_buffer(bytes),
        NotificationBatch::RescanRequired(_)
    ));
}

#[test]
fn parses_all_actions_as_independent_hints_not_a_rename_transaction() {
    let mut bytes = Vec::new();
    for action in 1..=5 {
        bytes.extend(record(action, "Folder\\hello-雪.txt", action != 5));
    }
    let NotificationBatch::Hints(hints) = parse_notification_buffer(&bytes) else {
        panic!("valid owned hints required");
    };
    assert_eq!(hints.len(), 5);
    assert_eq!(
        hints.iter().map(DirectoryHint::action).collect::<Vec<_>>(),
        [
            DirectoryAction::Added,
            DirectoryAction::Removed,
            DirectoryAction::Modified,
            DirectoryAction::RenamedOldName,
            DirectoryAction::RenamedNewName,
        ]
    );
    assert_eq!(hints[0].components(), ["Folder", "hello-雪.txt"]);
    assert!(!format!("{hints:?}").contains("hello"));
}

#[test]
fn empty_and_oversized_completions_require_reconciliation() {
    assert_eq!(
        parse_notification_buffer(&[]),
        NotificationBatch::RescanRequired(RescanReason::EmptyCompletion)
    );
    assert_eq!(
        parse_notification_buffer(&vec![0; NOTIFICATION_BUFFER_BYTES + 1]),
        NotificationBatch::RescanRequired(RescanReason::Limit)
    );
}

#[test]
fn rejects_every_truncated_header_and_filename() {
    let bytes = record(1, "abc.txt", false);
    for end in 1..bytes.len() {
        rejected(&bytes[..end]);
    }
    assert!(matches!(
        parse_notification_buffer(&bytes),
        NotificationBatch::Hints(_)
    ));
}

#[test]
fn rejects_unknown_actions_odd_lengths_and_invalid_utf16() {
    for action in [0, 6, u32::MAX] {
        rejected(&record(action, "x", false));
    }
    for length in [0, 1, 3, u32::MAX - 1, u32::MAX] {
        let mut bytes = record(1, "x", false);
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        rejected(&bytes);
    }
    for surrogate in [0xd800u16, 0xdc00] {
        let mut bytes = record(1, "x", false);
        bytes[12..14].copy_from_slice(&surrogate.to_le_bytes());
        rejected(&bytes);
    }
}

#[test]
fn rejects_relative_traversal_device_names_streams_and_ambiguous_components() {
    for name in [
        "",
        ".",
        "..",
        "x\\..\\y",
        "\\absolute",
        "C:\\x",
        "x/y",
        "x:stream",
        "x\\\\y",
        "x\\",
        "NUL.txt",
        "COM1",
        "LPT³.txt",
        "x.",
        "x ",
        "a\0b",
        "a\nb",
        "wild*",
        "bad?",
        "pipe|",
        "<x>",
        "quote\"",
    ] {
        rejected(&record(1, name, false));
    }
    rejected(&record(1, &"x".repeat(256), false));
    rejected(&record(1, &vec!["x"; MAX_COMPONENTS + 1].join("\\"), false));
}

#[test]
fn checked_offsets_refuse_overlap_misalignment_beyond_end_and_missing_next() {
    for offset in [1, 4, 12, 14, 15, 16, u32::MAX - 3, u32::MAX] {
        let mut bytes = record(1, "x", false);
        bytes[0..4].copy_from_slice(&offset.to_le_bytes());
        rejected(&bytes);
    }
    let mut bytes = record(1, "x", true);
    // An offset to EOF still promises a missing next record.
    rejected(&bytes);
    bytes.extend(record(3, "y", false));
    assert!(matches!(
        parse_notification_buffer(&bytes),
        NotificationBatch::Hints(_)
    ));
    bytes[16 + 4..16 + 8].copy_from_slice(&99u32.to_le_bytes());
    // Never return the valid prefix of a malformed batch.
    rejected(&bytes);
}

#[test]
fn final_alignment_padding_is_bounded_and_never_parsed_as_a_second_record() {
    for padding in [0, 2] {
        let mut bytes = record(1, "x", false);
        bytes.extend(std::iter::repeat_n(0xee, padding));
        assert!(matches!(
            parse_notification_buffer(&bytes),
            NotificationBatch::Hints(_)
        ));
    }
    for padding in [1, 3, 4] {
        let mut bytes = record(1, "x", false);
        bytes.extend(std::iter::repeat_n(0, padding));
        rejected(&bytes);
    }
    let mut bytes = record(1, "x", false);
    bytes.extend(record(2, "y", false));
    rejected(&bytes);
}

#[test]
fn explicit_hint_bound_discards_an_oversized_batch() {
    let mut bytes = Vec::new();
    for _ in 0..MAX_NOTIFICATION_HINTS {
        bytes.extend(record(1, "x", true));
    }
    bytes.extend(record(1, "x", false));
    assert_eq!(
        parse_notification_buffer(&bytes),
        NotificationBatch::RescanRequired(RescanReason::Limit)
    );
}

#[test]
fn input_does_not_need_native_pointer_alignment() {
    let mut unaligned = vec![0xff];
    unaligned.extend(record(1, "x", false));
    assert!(matches!(
        parse_notification_buffer(&unaligned[1..]),
        NotificationBatch::Hints(_)
    ));
}

#[test]
fn physical_directory_predicate_accepts_only_ordinary_and_all_documented_cloud_tags() {
    const DIRECTORY: u32 = 0x10;
    const REPARSE: u32 = 0x400;
    assert_eq!(directory_form(DIRECTORY, 0), Some(DirectoryForm::Ordinary));
    // Unrelated metadata attributes do not supply or revoke physical directory
    // type; this predicate does not classify provider ownership or encryption.
    assert_eq!(
        directory_form(DIRECTORY | 0x20, 0),
        Some(DirectoryForm::Ordinary)
    );
    for variant in 0..16 {
        let tag = 0x9000_001a | (variant << 12);
        assert_eq!(
            directory_form(DIRECTORY | REPARSE, tag),
            Some(DirectoryForm::Cloud)
        );
        assert_eq!(directory_form(DIRECTORY, tag), None);
        assert_eq!(directory_form(REPARSE, tag), None);
        assert_eq!(directory_form(DIRECTORY | REPARSE, tag | 0x2000_0000), None);
    }
}

#[test]
fn physical_directory_predicate_rejects_unknown_tags_and_inconsistent_types() {
    for (attributes, tag) in [
        (0, 0),
        (0x400, 0),
        (0x410, 0),
        (0x410, 0xa000_0003), // mount point / name surrogate
        (0x410, 0xa000_000c), // symlink / name surrogate
        (0x410, 0x9000_101b),
        (0x410, 0x9000_011a), // broad root mask alone would accept this unknown tag
        (0x410, 0x9001_001a),
        (0x410, 0x1000_001a),
        (0x410, 0x8000_001a),
        (0x410, u32::MAX),
        (0x10, 1),
    ] {
        assert_eq!(directory_form(attributes, tag), None);
    }
}

#[test]
fn observer_read_mask_and_closed_construction_stages() {
    // The notification read and its independent metadata validation both need
    // access on the newly opened handle; neither write nor DELETE is requested.
    assert_eq!(OBSERVER_ACCESS_MASK, 0x81);
    let stages = [
        ConstructionStage::OriginalMetadata,
        ConstructionStage::KernelPath,
        ConstructionStage::SameObjectOpen,
        ConstructionStage::ReopenedMetadata,
        ConstructionStage::OriginalPostMetadata,
        ConstructionStage::ReopenedPostMetadata,
        ConstructionStage::MetadataChanged,
        ConstructionStage::Event,
    ]
    .map(ConstructionStage::code);
    assert_eq!(
        stages,
        [
            "original_metadata",
            "kernel_path",
            "same_object_open",
            "reopened_metadata",
            "original_post_metadata",
            "reopened_post_metadata",
            "metadata_changed",
            "event"
        ]
    );
    let unique = stages.into_iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), 8);
}
