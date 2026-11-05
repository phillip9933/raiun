//! Read-only target binding for one original, SDK-qualified fresh create.
//! This is no authority to retry, complete or alter retained recovery records.

pub(crate) enum FreshCreateTargetKind {
    File,
    Directory,
}

pub(crate) struct FreshCreateTarget {
    parent_remote_id: String,
    components: Vec<String>,
    // Retain the original operation kind even though both kinds use the same
    // conservative overlap rule against an uncertain historical file create.
    _kind: FreshCreateTargetKind,
}

impl FreshCreateTarget {
    /// Call only with the retained checked SDK parent and original native leaf.
    /// Unicode remains valid input; it cannot establish the ASCII-only
    /// historical disjointness exception below.
    pub(crate) fn from_verified_parent(
        parent_path: &str,
        parent_remote_id: &str,
        name: &str,
        kind: FreshCreateTargetKind,
    ) -> Option<Self> {
        if parent_remote_id.is_empty()
            || parent_remote_id.len() > 4096
            || parent_remote_id.chars().any(char::is_control)
            || parent_path.len().checked_add(name.len())? > 32767
            || !crate::opencloud::valid_windows_component(name)
        {
            return None;
        }
        let parent = parent_path.strip_prefix('/')?;
        let mut components = if parent.is_empty() {
            Vec::new()
        } else {
            let parts: Vec<_> = parent.split('/').collect();
            if parts.len() >= 256
                || parts
                    .iter()
                    .any(|part| !crate::opencloud::valid_windows_component(part))
            {
                return None;
            }
            parts.into_iter().map(str::to_owned).collect()
        };
        components.push(name.to_owned());
        Some(Self {
            parent_remote_id: parent_remote_id.to_owned(),
            components,
            _kind: kind,
        })
    }

    /// Called only after authenticating the full historical namespace/snapshot
    /// join. Decline ambiguity rather than normalizing names or inferring old
    /// remote completion. Existing SDK/native/conditional-write checks remain
    /// mandatory for this exact new target.
    pub(crate) fn definitely_disjoint_from_file(
        &self,
        old_parent_remote_id: &str,
        old_name: &str,
        old_space_relative_path: &str,
    ) -> bool {
        if old_parent_remote_id.is_empty()
            || old_space_relative_path.len() > 32768
            || self
                .components
                .iter()
                .any(|part| !unambiguous_ascii_component(part))
        {
            return false;
        }
        let old: Vec<_> = old_space_relative_path.split('/').collect();
        if old.len() > 256
            || old.last().copied() != Some(old_name)
            || old.iter().any(|part| !unambiguous_ascii_component(part))
        {
            return false;
        }
        // Equal paths and either direction of ancestry remain held, including
        // paths whose parent identity changed since the original capture.
        if self
            .components
            .iter()
            .zip(&old)
            .all(|(new, old)| new.eq_ignore_ascii_case(old))
        {
            return false;
        }
        // A retained remote parent can have been renamed. A distinct spelling
        // of its old path never makes the same parent/name pair independent.
        !(self.parent_remote_id == old_parent_remote_id
            && self
                .components
                .last()
                .is_some_and(|new| new.eq_ignore_ascii_case(old_name)))
    }
}

fn unambiguous_ascii_component(value: &str) -> bool {
    crate::opencloud::valid_windows_component(value)
        && !value.starts_with(' ')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.' | b'(' | b')')
        })
        && !matches!(
            value
                .split('.')
                .next()
                .unwrap_or("")
                .trim_end_matches([' ', '.'])
                .to_ascii_uppercase()
                .as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}
