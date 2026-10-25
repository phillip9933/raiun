//! Connection-local history, never reconstructed from protected storage.
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
const MAX_RECEIPTS: usize = 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Reserved,
    Ready,
    EvictedUnconfirmed,
    Evicted,
    Invalidated,
}
pub(crate) struct Ticket {
    owner: Weak<()>,
    identity: [u8; 16],
    generation: u64,
}
struct Row<T> {
    generation: u64,
    phase: Phase,
    value: Option<Arc<T>>,
}
pub(crate) struct Receipts<T> {
    owner: Arc<()>,
    rows: BTreeMap<[u8; 16], Row<T>>,
    generation: u64,
    poisoned: bool,
}
impl<T> Default for Receipts<T> {
    fn default() -> Self {
        Self {
            owner: Arc::new(()),
            rows: BTreeMap::new(),
            generation: 0,
            poisoned: false,
        }
    }
}
impl<T> Receipts<T> {
    pub fn reserve(&mut self, identity: [u8; 16]) -> Result<Ticket, ()> {
        if self.poisoned
            || identity == [0; 16]
            || (!self.rows.contains_key(&identity) && self.rows.len() >= MAX_RECEIPTS)
        {
            return Err(());
        }
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
        })?;
        let generation = self.generation;
        self.rows.insert(
            identity,
            Row {
                generation,
                phase: Phase::Reserved,
                value: None,
            },
        );
        Ok(Ticket {
            owner: Arc::downgrade(&self.owner),
            identity,
            generation,
        })
    }
    fn row_mut(&mut self, ticket: &Ticket) -> Result<&mut Row<T>, ()> {
        if self.poisoned
            || !ticket.owner.ptr_eq(&Arc::downgrade(&self.owner))
            || ticket.owner.upgrade().is_none()
        {
            return Err(());
        }
        self.rows
            .get_mut(&ticket.identity)
            .filter(|r| r.generation == ticket.generation)
            .ok_or(())
    }
    pub fn publish(&mut self, ticket: Ticket, value: T) -> Result<(), ()> {
        let row = self.row_mut(&ticket)?;
        if row.phase != Phase::Reserved {
            return Err(());
        }
        row.value = Some(Arc::new(value));
        row.phase = Phase::Ready;
        Ok(())
    }
    /// Predicate checks the private full native context and existing Weak binding.
    pub fn admitted(
        &self,
        identity: &[u8; 16],
        mut matches: impl FnMut(&T) -> bool,
    ) -> Result<(Ticket, Arc<T>, bool), ()> {
        if self.poisoned {
            return Err(());
        }
        let row = self.rows.get(identity).ok_or(())?;
        let value = row.value.as_ref().ok_or(())?;
        if !matches!(
            row.phase,
            Phase::Ready | Phase::EvictedUnconfirmed | Phase::Evicted
        ) || !matches(value)
        {
            return Err(());
        }
        Ok((
            Ticket {
                owner: Arc::downgrade(&self.owner),
                identity: *identity,
                generation: row.generation,
            },
            Arc::clone(value),
            row.phase != Phase::Ready,
        ))
    }
    pub fn evicted_unconfirmed(&mut self, ticket: &Ticket) -> Result<(), ()> {
        let row = self.row_mut(ticket)?;
        if !matches!(
            row.phase,
            Phase::Ready | Phase::EvictedUnconfirmed | Phase::Evicted
        ) {
            return Err(());
        }
        row.phase = Phase::EvictedUnconfirmed;
        Ok(())
    }
    /// Validate the whole held span before changing any confirmation state.
    pub fn confirm(&mut self, tickets: &[&Ticket]) -> Result<(), ()> {
        if self.poisoned {
            return Err(());
        }
        for ticket in tickets {
            if self.row_mut(ticket)?.phase != Phase::EvictedUnconfirmed {
                return Err(());
            }
        }
        for ticket in tickets {
            self.row_mut(ticket)?.phase = Phase::Evicted;
        }
        Ok(())
    }
    pub fn invalidate(&mut self, identity: &[u8; 16]) {
        if let Some(row) = self.rows.get_mut(identity) {
            row.phase = Phase::Invalidated;
        }
    }
    pub fn invalidate_all(&mut self) {
        for row in self.rows.values_mut() {
            row.phase = Phase::Invalidated;
        }
    }
    pub fn contains(&self, identity: &[u8; 16]) -> bool {
        self.rows.contains_key(identity)
    }
    pub fn footprint(&self) -> bool {
        !self.rows.is_empty() || self.poisoned
    }
    pub fn incomplete(&self) -> bool {
        self.poisoned || self.rows.values().any(|r| r.phase != Phase::Evicted)
    }
    #[cfg(feature = "synthetic-agent-integration")]
    pub fn forget(&mut self, identity: &[u8; 16]) {
        self.rows.remove(identity);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_context_generation_and_invalidation() {
        let mut r = Receipts::default();
        assert!(!r.contains(&[1; 16]));
        let old = r.reserve([1; 16]).unwrap();
        assert!(r.contains(&[1; 16]));
        let current = r.reserve([1; 16]).unwrap();
        assert!(r.publish(old, 7).is_err());
        r.publish(current, 9).unwrap();
        assert!(r.admitted(&[1; 16], |v| *v == 7).is_err());
        assert!(r.admitted(&[2; 16], |_| true).is_err());
        let (ticket, _, empty) = r.admitted(&[1; 16], |v| *v == 9).unwrap();
        assert!(!empty);
        r.evicted_unconfirmed(&ticket).unwrap();
        assert!(r.incomplete());
        r.invalidate(&[1; 16]);
        assert!(r.confirm(&[&ticket]).is_err());
        assert!(r.admitted(&[1; 16], |_| true).is_err());
    }
    #[test]
    fn abandoned_eviction_is_not_confirmation_and_whole_batch_is_atomic() {
        let mut r = Receipts::default();
        for n in [1, 2] {
            let t = r.reserve([n; 16]).unwrap();
            r.publish(t, n).unwrap();
        }
        let (a, _, _) = r.admitted(&[1; 16], |_| true).unwrap();
        r.evicted_unconfirmed(&a).unwrap();
        assert!(r.admitted(&[1; 16], |_| true).unwrap().2);
        assert!(r.incomplete());
        let (b, _, _) = r.admitted(&[2; 16], |_| true).unwrap();
        assert!(r.confirm(&[&a, &b]).is_err());
        assert!(r.incomplete());
        r.evicted_unconfirmed(&b).unwrap();
        r.confirm(&[&a, &b]).unwrap();
        assert!(!r.incomplete());
        assert!(r.footprint());
        r.invalidate_all();
        assert!(r.incomplete());
    }
    #[test]
    fn bounded_without_eviction_and_weak_context_does_not_adopt_replacement() {
        let binding = Arc::new(());
        let weak = Arc::downgrade(&binding);
        let mut r = Receipts::default();
        let t = r.reserve([1; 16]).unwrap();
        r.publish(t, weak).unwrap();
        let replacement = Arc::new(());
        assert!(
            r.admitted(&[1; 16], |w| w.ptr_eq(&Arc::downgrade(&replacement)))
                .is_err()
        );
        drop(binding);
        assert!(r.admitted(&[1; 16], |w| w.upgrade().is_some()).is_err());
        let mut r = Receipts::<()>::default();
        for i in 1..=MAX_RECEIPTS {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            r.reserve(id).unwrap();
        }
        assert!(r.reserve([255; 16]).is_err());
        assert_eq!(r.rows.len(), MAX_RECEIPTS);
        assert!(r.incomplete());
    }
    #[test]
    fn foreign_or_expired_book_tickets_and_empty_poison_refuse() {
        let mut a = Receipts::<()>::default();
        let mut b = Receipts::<()>::default();
        let foreign = a.reserve([1; 16]).unwrap();
        let own = b.reserve([1; 16]).unwrap();
        assert!(b.publish(foreign, ()).is_err());
        b.publish(own, ()).unwrap();
        let expired = a.reserve([2; 16]).unwrap();
        drop(a);
        assert!(expired.owner.upgrade().is_none());
        assert!(b.publish(expired, ()).is_err());
        b.generation = u64::MAX;
        assert!(b.reserve([3; 16]).is_err());
        assert!(b.confirm(&[]).is_err());
    }
}
