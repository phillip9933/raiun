//! Non-admitting physical entry kinds. A cloud-shaped entry is not proof of
//! provider ownership, clean content, completed upload or mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceEntryKind {
    PlainFile,
    PlainDirectory,
    CloudFile,
    CloudDirectory,
}

pub(crate) fn classify(
    attributes: u32,
    reparse_tag: u32,
    placeholder_state: u32,
    cloud_tag: bool,
) -> Option<NamespaceEntryKind> {
    let directory = attributes & 0x10 != 0;
    if attributes & 0x400 == 0 {
        if reparse_tag != 0 || placeholder_state != 0 || cloud_tag {
            return None;
        }
        return Some(if directory {
            NamespaceEntryKind::PlainDirectory
        } else {
            NamespaceEntryKind::PlainFile
        });
    }
    if !cloud_tag
        || reparse_tag == 0
        || placeholder_state & 1 == 0
        || placeholder_state & 2 != 0
        || placeholder_state & !0x3f != 0
    {
        return None;
    }
    Some(if directory {
        NamespaceEntryKind::CloudDirectory
    } else {
        NamespaceEntryKind::CloudFile
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_entries_require_consistent_non_reparse_metadata() {
        assert_eq!(
            classify(0x20, 0, 0, false),
            Some(NamespaceEntryKind::PlainFile)
        );
        assert_eq!(
            classify(0x10, 0, 0, false),
            Some(NamespaceEntryKind::PlainDirectory)
        );
        for (tag, state, cloud) in [(1, 0, false), (0, 1, false), (0, 0, true)] {
            assert_eq!(classify(0x10, tag, state, cloud), None);
        }
    }
    #[test]
    fn cloud_entries_remain_distinct_from_plain_entries() {
        for state in [1, 9, 0x11, 0x21, 0x3d] {
            assert_eq!(
                classify(0x400, 0x9000001a, state, true),
                Some(NamespaceEntryKind::CloudFile)
            );
            assert_eq!(
                classify(0x410, 0x9000001a, state, true),
                Some(NamespaceEntryKind::CloudDirectory)
            );
        }
    }
    #[test]
    fn unknown_reparse_sync_root_and_invalid_state_are_not_classified() {
        for (attributes, tag, state, cloud) in [
            (0x410, 0xa000000c, 0, false),
            (0x410, 0, 1, true),
            (0x410, 0x9000001a, 0, true),
            (0x410, 0x9000001a, 3, true),
            (0x410, 0x9000001a, 0x41, true),
            (0x410, 0x9000001a, u32::MAX, true),
        ] {
            assert_eq!(classify(attributes, tag, state, cloud), None);
        }
    }
}
