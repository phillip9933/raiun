//! Process-local routing identity, never a key, lease or upload permission.
use std::sync::{Arc, Weak};

/// One capture's original immutable vault binding. It cannot be reconstructed
/// from retained history or keep a session/key bundle alive. The receiving live
/// binding must still acquire its normal account/token/opaque-epoch guards.
/// Intentionally no public constructor, Clone, Debug or serialization.
pub struct FreshVaultCaptureDispatch {
    binding: Weak<()>,
}

impl FreshVaultCaptureDispatch {
    pub(crate) fn from_binding(binding: &Arc<()>) -> Self {
        Self {
            binding: Arc::downgrade(binding),
        }
    }

    pub(crate) fn matches_binding(&self, binding: &Arc<()>) -> bool {
        Weak::ptr_eq(&self.binding, &Arc::downgrade(binding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_event_cannot_adopt_a_replaced_binding() {
        let original = Arc::new(());
        let event = FreshVaultCaptureDispatch::from_binding(&original);
        assert!(event.matches_binding(&original));
        let replacement = Arc::new(());
        assert!(!event.matches_binding(&replacement));
        drop(original);
        assert!(!event.matches_binding(&replacement));
    }
}
