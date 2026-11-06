//! Read-only target binding for one original, SDK-qualified fresh create.
//! This is no authority to retry, complete or alter retained recovery records.

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FreshCreateTargetKind {
    File,
    Directory,
}

/// Immutable join facts only, never a cached health result or native authority.
/// Mint only from actual worker-local metadata pins, retain those pins during
/// the health query, then join ALL facts to the owner's later actual pins.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativeCreateFacts {
    root: crate::ConfiguredRootIdentity,
    components: Vec<String>,
    kind: FreshCreateTargetKind,
    leaf: crate::LocalFileIdentity,
    parents: Vec<crate::LocalFileIdentity>,
}
impl NativeCreateFacts {
    #[cfg(windows)]
    pub(crate) fn from_checked_pins(
        root: crate::ConfiguredRootIdentity,
        components: Vec<String>,
        kind: FreshCreateTargetKind,
        leaf: crate::LocalFileIdentity,
        parents: Vec<crate::LocalFileIdentity>,
    ) -> Option<Self> {
        if root.file_index == 0
            || components.is_empty()
            || components.len() > 256
            || components
                .iter()
                .any(|p| !crate::opencloud::valid_windows_component(p))
            || parents.len() != components.len()
            || parents.first()
                != Some(&crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: root.file_index,
                })
        {
            return None;
        }
        let mut unique = std::collections::HashSet::new();
        if parents.iter().chain(std::iter::once(&leaf)).any(|id| {
            id.volume_serial != root.volume_serial
                || id.file_index == 0
                || !unique.insert((id.volume_serial, id.file_index))
        }) {
            return None;
        }
        Some(Self {
            root,
            components,
            kind,
            leaf,
            parents,
        })
    }
    #[cfg(windows)]
    pub(crate) fn matches(
        &self,
        root: crate::ConfiguredRootIdentity,
        components: &[String],
        kind: FreshCreateTargetKind,
        leaf: crate::LocalFileIdentity,
        parents: &[crate::LocalFileIdentity],
    ) -> bool {
        self.root == root
            && self.components == components
            && self.kind == kind
            && self.leaf == leaf
            && self.parents == parents
    }
}

pub(crate) struct FreshCreateTarget {
    parent_remote_id: String,
    components: Vec<String>,
    // One original SDK capture only; absent proof keeps directory history held.
    verified_ancestry: Option<(String, Vec<String>)>,
    native_custody: Option<NativeCreateFacts>,
    // Retain the original operation kind even though both kinds use the same
    // conservative overlap rule against an uncertain historical file create.
    _kind: FreshCreateTargetKind,
}

impl FreshCreateTarget {
    /// Call only with the retained checked SDK parent and original native leaf.
    /// Unicode remains valid input; it cannot establish the ASCII-only prefix
    /// or same-parent leaf proofs used for historical disjointness below.
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
            verified_ancestry: None,
            native_custody: None,
            _kind: kind,
        })
    }

    #[cfg(windows)]
    pub(crate) fn bind_native_custody(
        &mut self,
        scope: &crate::EditJournalScope,
        facts: &NativeCreateFacts,
    ) -> Option<()> {
        let (leaf, parent) = facts.components.split_last()?;
        let parent: Vec<_> = parent.iter().map(String::as_str).collect();
        let relative = crate::personal_create_relative(&parent, leaf)?;
        if facts.root.volume_serial != scope.root_volume_serial
            || facts.root.file_index != scope.root_file_index
            || facts.kind != self._kind
            || self
                .components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != relative.split('/').collect::<Vec<_>>()
        {
            return None;
        }
        self.native_custody = Some(facts.clone());
        Some(())
    }

    /// Add-only isolation for an authenticated unfinished directory. This is
    /// not a claim that its unknown remote child is outside the remote tree.
    /// Every other health/native/conditional-create gate remains required.
    pub(crate) fn permits_additive_beside_directory(
        &self,
        old_parent_components: &[String],
        old_parent_remote_id: &str,
        old_name: &str,
        old_native: crate::LocalFileIdentity,
        root_resource_id: &str,
    ) -> bool {
        let Some(facts) = self.native_custody.as_ref() else {
            return false;
        };
        let Some((root, _)) = self.verified_ancestry.as_ref() else {
            return false;
        };
        if root != root_resource_id
            || old_native.file_index == 0
            || old_native.volume_serial != facts.root.volume_serial
            || facts.leaf == old_native
            || facts.parents.contains(&old_native)
        {
            return false;
        }
        self.disjoint_directory_spelling(
            old_parent_components,
            old_parent_remote_id,
            old_name,
            root_resource_id,
        )
    }

    /// Bind the complete freshly stat-verified remote chain from Space root
    /// through this parent. No persistent ancestry cache or recovery authority.
    pub(crate) fn with_verified_parent_ancestry(
        mut self,
        root_resource_id: &str,
        ancestors: &[String],
    ) -> Option<Self> {
        if !checked_remote_id(root_resource_id)
            || ancestors.len() != self.components.len()
            || ancestors.first().map(String::as_str) != Some(root_resource_id)
            || ancestors.last() != Some(&self.parent_remote_id)
            || ancestors.iter().any(|id| !checked_remote_id(id))
        {
            return None;
        }
        let mut unique = std::collections::HashSet::new();
        if ancestors.iter().any(|id| !unique.insert(id)) {
            return None;
        }
        self.verified_ancestry = Some((root_resource_id.to_owned(), ancestors.to_vec()));
        Some(self)
    }

    /// Only a fully authenticated Verified/sequence-2 directory report may call
    /// this classifier. A past created directory cannot contain this fresh
    /// parent when its stable child ID is absent from the COMPLETE fresh chain.
    /// Conservative spelling and same-parent alias checks remain independent.
    pub(crate) fn definitely_disjoint_from_verified_directory(
        &self,
        old_parent_components: &[String],
        old_parent_remote_id: &str,
        old_name: &str,
        verified_child_id: &str,
        root_resource_id: &str,
    ) -> bool {
        let Some((checked_root, ancestors)) = self.verified_ancestry.as_ref() else {
            return false;
        };
        if checked_root != root_resource_id
            || !checked_remote_id(verified_child_id)
            || verified_child_id == root_resource_id
            || verified_child_id == old_parent_remote_id
            || ancestors.iter().any(|id| id == verified_child_id)
        {
            return false;
        }
        self.disjoint_directory_spelling(
            old_parent_components,
            old_parent_remote_id,
            old_name,
            root_resource_id,
        )
    }

    fn disjoint_directory_spelling(
        &self,
        old_parent_components: &[String],
        old_parent_remote_id: &str,
        old_name: &str,
        root_resource_id: &str,
    ) -> bool {
        let parent: Vec<_> = old_parent_components.iter().map(String::as_str).collect();
        let prefix = match parent.first().copied() {
            Some("Personal") => 1,
            Some("Spaces") if parent.len() >= 2 => 2,
            _ => return false,
        };
        let Some(relative) = crate::personal_create_relative(&parent, old_name) else {
            return false;
        };
        // An authenticated but topologically inconsistent old parent is held.
        if (parent.len() == prefix) != (old_parent_remote_id == root_resource_id) {
            return false;
        }
        self.definitely_disjoint_from_file(old_parent_remote_id, old_name, &relative)
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
            || old_parent_remote_id.len() > 4096
            || old_parent_remote_id.chars().any(char::is_control)
            || self.parent_remote_id.is_empty()
            || self.parent_remote_id.len() > 4096
            || self.parent_remote_id.chars().any(char::is_control)
            || old_space_relative_path.is_empty()
            || old_space_relative_path.len() > 32768
            || self.components.is_empty()
            || self.components.len() > 256
            || self
                .components
                .iter()
                .any(|part| !crate::opencloud::valid_windows_component(part))
            || self.components.iter().map(String::len).sum::<usize>() + self.components.len() - 1
                > 32767
        {
            return false;
        }
        let old: Vec<_> = old_space_relative_path.split('/').collect();
        if old.len() > 256
            || old.last().copied() != Some(old_name)
            || old
                .iter()
                .any(|part| !crate::opencloud::valid_windows_component(part))
        {
            return false;
        }
        // Validate every suffix structurally above, but use only a proven ASCII
        // prefix through its first distinct sibling to establish disjointness.
        let mut distinct_prefix = false;
        for (new, old) in self.components.iter().zip(&old) {
            if !unambiguous_ascii_component(new) || !unambiguous_ascii_component(old) {
                return false;
            }
            if !new.eq_ignore_ascii_case(old) {
                distinct_prefix = true;
                break;
            }
        }
        // Equal paths and either direction of ancestry remain held, including
        // paths whose parent identity changed since the original capture.
        if !distinct_prefix {
            return false;
        }
        // A retained remote parent can have been renamed. A distinct spelling
        // of its old path needs an independent ASCII-distinct leaf proof.
        if self.parent_remote_id == old_parent_remote_id {
            return self.components.last().is_some_and(|new| {
                unambiguous_ascii_component(new)
                    && unambiguous_ascii_component(old_name)
                    && !new.eq_ignore_ascii_case(old_name)
            });
        }
        true
    }
}

fn checked_remote_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
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
