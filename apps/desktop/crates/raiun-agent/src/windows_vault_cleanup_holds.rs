//! Finite owner-thread holds, not cleanup authority. The provider must separately
//! validate its exact binding, backend and scope before consuming a ticket.
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

const CAPACITY: usize = 64;
const LIFETIME: Duration = Duration::from_secs(30);

struct Nonce;

/// Only the owner book retains a strong nonce. Dropping the non-cloneable
/// caller ticket makes the hold eligible for the next owner-thread sweep.
pub(super) struct PendingCleanupTicket {
    nonce: Weak<Nonce>,
}

struct Row<T> {
    nonce: Arc<Nonce>,
    value: T,
    deadline: Instant,
}

/// T deliberately has no Send bound: referenced native files remain on their
/// provider owner thread. No timer, native I/O or cross-thread ownership exists.
pub(super) struct PendingCleanupHolds<T> {
    rows: Vec<Row<T>>,
}

impl<T> Default for PendingCleanupHolds<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PendingCleanupHolds<T> {
    pub(super) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.rows.len() < CAPACITY
    }

    pub(super) fn any(&self, mut predicate: impl FnMut(&T) -> bool) -> bool {
        self.rows.iter().any(|row| predicate(&row.value))
    }

    pub(super) fn insert(&mut self, value: T, now: Instant) -> Result<PendingCleanupTicket, T> {
        let Some(deadline) = now.checked_add(LIFETIME) else {
            return Err(value);
        };
        if !self.has_capacity() {
            return Err(value);
        }
        let nonce = Arc::new(Nonce);
        let ticket = PendingCleanupTicket {
            nonce: Arc::downgrade(&nonce),
        };
        self.rows.push(Row {
            nonce,
            value,
            deadline,
        });
        Ok(ticket)
    }

    pub(super) fn take(&mut self, ticket: PendingCleanupTicket, now: Instant) -> Option<T> {
        let index = self.index(&ticket)?;
        let row = self.rows.swap_remove(index);
        if now >= row.deadline {
            // Release the owned guard before returning refusal. Expired tickets
            // can never hand a still-held native fence to completion.
            drop(row);
            return None;
        }
        Some(row.value)
    }

    pub(super) fn abort(&mut self, ticket: PendingCleanupTicket) -> bool {
        let Some(index) = self.index(&ticket) else {
            return false;
        };
        drop(self.rows.swap_remove(index));
        true
    }

    pub(super) fn sweep(&mut self, now: Instant) -> usize {
        let before = self.rows.len();
        self.rows
            .retain(|row| now < row.deadline && Arc::weak_count(&row.nonce) != 0);
        before - self.rows.len()
    }

    pub(super) fn clear(&mut self) {
        self.rows.clear();
    }

    fn index(&self, ticket: &PendingCleanupTicket) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| Weak::as_ptr(&ticket.nonce) == Arc::as_ptr(&row.nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    // Rc makes this an owner-thread-only fake native guard. Its drop signal
    // distinguishes releasing a hold from merely removing a locator.
    struct Guard {
        id: usize,
        drops: Rc<Cell<usize>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    fn guard(id: usize, drops: &Rc<Cell<usize>>) -> Guard {
        Guard {
            id,
            drops: Rc::clone(drops),
        }
    }
    fn inserted(
        book: &mut PendingCleanupHolds<Guard>,
        value: Guard,
        now: Instant,
    ) -> PendingCleanupTicket {
        match book.insert(value, now) {
            Ok(ticket) => ticket,
            Err(_) => panic!("test insertion must fit"),
        }
    }

    #[test]
    fn take_transfers_once_and_stale_nonce_cannot_consume_a_replacement() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut book = PendingCleanupHolds::new();
        let ticket = inserted(&mut book, guard(1, &drops), now);
        // Test-only duplicate to exercise stale nonce rejection. Production
        // tickets have no Clone implementation or public constructor.
        let stale = PendingCleanupTicket {
            nonce: ticket.nonce.clone(),
        };
        let value = book.take(ticket, now).expect("live ticket");
        assert_eq!(value.id, 1);
        assert_eq!(drops.get(), 0);
        let replacement = inserted(&mut book, guard(2, &drops), now);
        assert!(book.take(stale, now).is_none());
        assert!(book.any(|value| value.id == 2));
        assert!(book.abort(replacement));
        assert_eq!(drops.get(), 1);
        drop(value);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn caller_loss_sweep_drops_only_abandoned_hold() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut book = PendingCleanupHolds::default();
        let abandoned = inserted(&mut book, guard(1, &drops), now);
        let retained = inserted(&mut book, guard(2, &drops), now);
        drop(abandoned);
        assert_eq!(book.sweep(now), 1);
        assert_eq!(drops.get(), 1);
        assert!(book.any(|value| value.id == 2));
        assert_eq!(book.sweep(now), 0);
        assert!(book.abort(retained));
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn exact_deadline_take_and_sweep_release_without_returning_guard() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut book = PendingCleanupHolds::new();
        let before = inserted(&mut book, guard(1, &drops), now);
        let expired = inserted(&mut book, guard(2, &drops), now);
        let swept = inserted(&mut book, guard(3, &drops), now);
        let value = book
            .take(before, now + LIFETIME - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(value.id, 1);
        assert!(book.take(expired, now + LIFETIME).is_none());
        assert_eq!(drops.get(), 1);
        assert_eq!(book.sweep(now + LIFETIME), 1);
        assert_eq!(drops.get(), 2);
        assert!(book.take(swept, now + LIFETIME).is_none());
        drop(value);
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn failed_response_send_can_abort_immediately() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut book = PendingCleanupHolds::new();
        let ticket = inserted(&mut book, guard(1, &drops), now);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let error = sender.send(ticket).expect_err("receiver gone");
        assert!(book.abort(error.0));
        assert_eq!(drops.get(), 1);
        assert_eq!(book.sweep(now), 0);
    }

    #[test]
    fn capacity_never_evicts_or_consumes_rejected_value() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut book = PendingCleanupHolds::new();
        let tickets: Vec<_> = (0..CAPACITY)
            .map(|id| inserted(&mut book, guard(id, &drops), now))
            .collect();
        assert!(!book.has_capacity());
        let rejected = match book.insert(guard(CAPACITY, &drops), now) {
            Err(value) => value,
            Ok(_) => panic!("must refuse beyond fixed capacity"),
        };
        assert_eq!(drops.get(), 0);
        assert_eq!(rejected.id, CAPACITY);
        assert!(book.any(|value| value.id == 0));
        assert!(book.any(|value| value.id == CAPACITY - 1));
        drop(rejected);
        assert_eq!(drops.get(), 1);
        assert!(book.abort(tickets.into_iter().next().unwrap()));
        assert!(book.has_capacity());
        book.clear();
        assert_eq!(drops.get(), CAPACITY + 1);
    }

    #[test]
    fn foreign_book_cannot_take_or_abort_and_clear_releases_before_return() {
        let now = Instant::now();
        let drops = Rc::new(Cell::new(0));
        let mut first = PendingCleanupHolds::new();
        let mut second = PendingCleanupHolds::new();
        let own = inserted(&mut first, guard(1, &drops), now);
        let foreign = inserted(&mut second, guard(2, &drops), now);
        let foreign_abort = PendingCleanupTicket {
            nonce: foreign.nonce.clone(),
        };
        assert!(first.take(foreign, now).is_none());
        assert!(!first.abort(foreign_abort));
        assert_eq!(drops.get(), 0);
        assert_eq!(second.sweep(now), 1);
        first.clear();
        assert_eq!(drops.get(), 2);
        assert!(first.take(own, now).is_none());
        assert!(!first.any(|_| true));
    }
}
