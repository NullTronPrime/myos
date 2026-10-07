//! Scheduler: run queues, process states, and a deterministic fake clock.
//!
//! No timers and no threads here. Time advances only when the test says so,
//! which is what makes starvation and priority-inversion bugs reproducible
//! instead of intermittent.

use std::collections::BTreeMap;

/// Process identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Pid(pub u32);

/// Run states, following the usual Unix taxonomy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Eligible to run.
    Ready,
    /// Waiting on an event.
    Blocked,
    /// Deliberately stopped.
    Stopped,
    /// Finished. Terminal.
    Zombie,
    /// Never scheduled.
    New,
}

impl State {
    /// True when the task can be picked up by the scheduler.
    pub fn is_runnable(self) -> bool {
        matches!(self, State::Ready)
    }

    /// True when the task can never run again.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Zombie)
    }
}

/// One schedulable thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub pid: Pid,
    pub state: State,
    /// Remaining ticks in the current quantum.
    pub quantum_left: u32,
    /// Scheduling weight. Higher runs more often at equal priority class.
    pub priority: u32,
    /// What the task is blocked on, for diagnostics and assertions.
    pub blocked_on: Option<BlockReason>,
    /// Ticks spent runnable without being dispatched. Drives priority aging.
    pub waited: u64,
    /// Ticks this task has actually consumed.
    pub ran: u64,
}

/// Why a task is blocked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockReason {
    /// Waiting on an I/O completion.
    Io,
    /// Waiting for another task to exit.
    WaitChild,
    /// Sleeping until the clock reaches a tick.
    Sleep,
    /// Waiting on a futex.
    Futex,
}

/// Default tick budget handed to a task per dispatch.
pub const DEFAULT_QUANTUM: u32 = 4;

/// Errors the scheduler reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SchedError {
    NoPidAllocated,
    NoSuchPid,
    AlreadyExists,
    InvalidTransition,
    QueueCorrupt,
}

/// Round-robin scheduler with per-priority run queues.
///
/// The current task is modelled explicitly so that the "what runs next after
/// the quantum expires" question has one unambiguous answer, which is the part
/// schedulers usually get wrong.
pub struct Scheduler {
    tasks: BTreeMap<u32, Task>,
    queues: BTreeMap<u32, Vec<Pid>>,
    current: Option<Pid>,
    next_pid: u32,
    clock: u64,
    /// Ticks consumed by the current dispatch.
    elapsed: u32,
    pub quantum: u32,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            tasks: BTreeMap::new(),
            queues: BTreeMap::new(),
            current: None,
            next_pid: 1,
            clock: 0,
            elapsed: 0,
            quantum: DEFAULT_QUANTUM,
        }
    }

    /// Current fake time in ticks.
    pub fn clock(&self) -> u64 {
        self.clock
    }

    pub fn current(&self) -> Option<Pid> {
        self.current
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn get(&self, pid: Pid) -> Result<&Task, SchedError> {
        self.tasks.get(&pid.0).ok_or(SchedError::NoSuchPid)
    }

    fn get_mut(&mut self, pid: Pid) -> Result<&mut Task, SchedError> {
        self.tasks.get_mut(&pid.0).ok_or(SchedError::NoSuchPid)
    }

    /// Adds a task in `New` state with the given priority.
    pub fn spawn(&mut self, priority: u32) -> Pid {
        let pid = Pid(self.next_pid);
        self.next_pid += 1;
        self.tasks.insert(
            pid.0,
            Task {
                pid,
                state: State::New,
                quantum_left: self.quantum,
                priority,
                blocked_on: None,
                waited: 0,
                ran: 0,
            },
        );
        pid
    }

    /// Moves a task into a run queue.
    pub fn make_ready(&mut self, pid: Pid) -> Result<(), SchedError> {
        let quantum = self.quantum;
        let priority = {
            let t = self.get_mut(pid)?;
            if t.state.is_terminal() {
                return Err(SchedError::InvalidTransition);
            }
            t.state = State::Ready;
            t.quantum_left = quantum;
            t.blocked_on = None;
            t.priority
        };
        self.queues.entry(priority).or_default().push(pid);
        Ok(())
    }

    /// Takes a task out of every run queue, for state changes.
    fn dequeue(&mut self, pid: Pid) {
        for q in self.queues.values_mut() {
            if let Some(i) = q.iter().position(|p| *p == pid) {
                q.remove(i);
                return;
            }
        }
    }

    /// Blocks a task on a reason.
    pub fn block(&mut self, pid: Pid, reason: BlockReason) -> Result<(), SchedError> {
        self.dequeue(pid);
        let t = self.get_mut(pid)?;
        if t.state.is_terminal() {
            return Err(SchedError::InvalidTransition);
        }
        t.state = State::Blocked;
        t.blocked_on = Some(reason);
        Ok(())
    }

    /// Suspends a task without removing it from the ready set conceptually;
    /// a stopped task becomes runnable again via `make_ready`.
    pub fn stop(&mut self, pid: Pid) -> Result<(), SchedError> {
        self.dequeue(pid);
        let t = self.get_mut(pid)?;
        t.state = State::Stopped;
        Ok(())
    }

    /// Marks a task finished. Zombie is terminal.
    pub fn exit(&mut self, pid: Pid) -> Result<(), SchedError> {
        self.dequeue(pid);
        if self.current == Some(pid) {
            self.current = None;
        }
        let t = self.get_mut(pid)?;
        if t.state.is_terminal() {
            return Err(SchedError::InvalidTransition);
        }
        t.state = State::Zombie;
        t.blocked_on = None;
        Ok(())
    }

    /// Changes a task's priority, moving it between queues if runnable.
    pub fn set_priority(&mut self, pid: Pid, priority: u32) -> Result<(), SchedError> {
        let was_runnable = self.get(pid)?.state.is_runnable();
        if was_runnable {
            self.dequeue(pid);
        }
        self.get_mut(pid)?.priority = priority;
        if was_runnable {
            self.queues.entry(priority).or_default().push(pid);
        }
        Ok(())
    }

    /// Wakes every task sleeping until `deadline`.
    pub fn wake_sleepers(&mut self, now: u64) -> Vec<Pid> {
        let due: Vec<Pid> = self
            .tasks
            .values()
            .filter(|t| t.state == State::Blocked && t.blocked_on == Some(BlockReason::Sleep))
            .map(|t| t.pid)
            .collect();
        // Sleeping tasks carry their deadline in quantum_left slots; those at or
        // past `now` become ready. Deadline 0 means "any time", so it wakes.
        let mut woken = Vec::new();
        for pid in due {
            let ready = self
                .get(pid)
                .map(|t| t.quantum_left as u64 <= now)
                .unwrap_or(false);
            if ready && self.make_ready(pid).is_ok() {
                woken.push(pid);
            }
        }
        woken
    }

    /// Number of runnable tasks.
    pub fn runnable_count(&self) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state.is_runnable())
            .count()
    }

    /// Number of tasks in a given priority queue, runnable only.
    pub fn queue_len(&self, priority: u32) -> usize {
        self.queues.get(&priority).map(|q| q.len()).unwrap_or(0)
    }

    /// Ticks of waiting that earn one point of priority boost.
    ///
    /// With the default of 8, a task that waits 24 ticks without running gains
    /// three priority points, which is enough to outrank a modestly higher
    /// priority task that is monopolising the CPU.
    pub const AGING_PERIOD: u64 = 8;

    /// Effective priority of a runnable task, including its aging boost.
    pub fn effective_priority(&self, pid: Pid) -> Option<u64> {
        let t = self.tasks.get(&pid.0)?;
        if !t.state.is_runnable() {
            return None;
        }
        Some(t.priority as u64 + t.waited / Self::AGING_PERIOD)
    }

    /// Picks the highest-priority runnable task, breaking ties by longest wait.
    ///
    /// Priority is the *effective* priority, so a runnable task that has been
    /// skipped for a long time is promoted rather than starving behind a
    /// steady stream of higher-priority work.
    ///
    /// Returns `None` when nothing is runnable, which is the signal that the
    /// machine is idle.
    pub fn pick_next(&mut self) -> Option<Pid> {
        // First find the best effective priority among runnable tasks.
        let mut best_eff: Option<u64> = None;
        for t in self.tasks.values() {
            if !t.state.is_runnable() {
                continue;
            }
            let eff = t.priority as u64 + t.waited / Self::AGING_PERIOD;
            best_eff = Some(match best_eff {
                Some(cur) => cur.max(eff),
                None => eff,
            });
        }
        let best_eff = best_eff?;

        // Then take the task sitting earliest in the run queue among those at
        // that effective priority. Ordering by queue position rather than by pid
        // is what preserves round-robin: the previous dispatch moved itself to
        // the back, so the front is whoever has waited longest for a turn.
        let mut chosen: Option<(usize, u32, Pid)> = None;
        for (prio, q) in &self.queues {
            for (i, pid) in q.iter().enumerate() {
                let t = match self.tasks.get(&pid.0) {
                    Some(t) if t.state.is_runnable() => t,
                    _ => continue,
                };
                let eff = t.priority as u64 + t.waited / Self::AGING_PERIOD;
                if eff != best_eff {
                    continue;
                }
                let cand = (i, *prio, *pid);
                chosen = match chosen {
                    None => Some(cand),
                    Some(cur) => {
                        let better = cand.0 < cur.0 || (cand.0 == cur.0 && cand.2 < cur.2);
                        if better {
                            Some(cand)
                        } else {
                            Some(cur)
                        }
                    }
                };
            }
        }

        let (_, base_priority, pid) = chosen?;

        // Move the chosen task to the back of its own queue so peers get a turn.
        if let Some(q) = self.queues.get_mut(&base_priority) {
            if let Some(i) = q.iter().position(|x| *x == pid) {
                q.remove(i);
                q.push(pid);
            }
        }

        let quantum = self.quantum;
        self.current = Some(pid);
        if let Ok(t) = self.get_mut(pid) {
            t.quantum_left = quantum;
            t.waited = 0;
        }
        self.elapsed = 0;
        Some(pid)
    }

    /// Accounts for one tick of execution by the current task.
    ///
    /// Every other runnable task accrues a wait tick, so aging reflects real
    /// elapsed time rather than dispatch count.
    ///
    /// Returns `true` when the quantum is exhausted and a reschedule is due.
    pub fn tick(&mut self) -> Result<bool, SchedError> {
        self.clock += 1;
        self.elapsed += 1;
        let cur = self.current.ok_or(SchedError::NoPidAllocated)?;
        let quantum = self.quantum;
        let elapsed = self.elapsed;

        let exhausted;
        {
            let t = self.get_mut(cur)?;
            if t.state != State::Ready {
                // A task that blocked mid-quantum stops consuming budget.
                exhausted = false;
            } else {
                t.ran += 1;
                if t.quantum_left > 0 {
                    t.quantum_left -= 1;
                }
                exhausted = elapsed >= quantum || t.quantum_left == 0;
            }
        }

        for t in self.tasks.values_mut() {
            if t.pid != cur && t.state.is_runnable() {
                t.waited += 1;
            }
        }

        Ok(exhausted)
    }

    /// Total ticks each task has consumed. Only meaningful with the fake clock.
    pub fn cpu_ticks(&self) -> BTreeMap<u32, u64> {
        self.tasks.values().map(|t| (t.pid.0, t.ran)).collect()
    }

    /// Runs `steps` scheduling decisions, dispatching in between.
    ///
    /// A `trace` callback observes each dispatch, which is how tests assert on
    /// fairness properties without racing anything.
    pub fn run_until_idle<F: FnMut(Pid)>(&mut self, max_steps: u64, mut on_dispatch: F) {
        for _ in 0..max_steps {
            match self.pick_next() {
                Some(pid) => {
                    on_dispatch(pid);
                    let _ = self.tick();
                }
                None => return,
            }
        }
    }

    /// Detects the same pid appearing twice in one queue, which would silently
    /// break fairness. Cheap enough to run after every operation in tests.
    pub fn validate(&self) -> Result<(), SchedError> {
        for (prio, q) in &self.queues {
            for (i, pid) in q.iter().enumerate() {
                if q[i + 1..].contains(pid) {
                    return Err(SchedError::QueueCorrupt);
                }
                let t = self.get(*pid)?;
                if !t.state.is_runnable() {
                    return Err(SchedError::QueueCorrupt);
                }
                if t.priority != *prio {
                    return Err(SchedError::QueueCorrupt);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records the dispatch order for assertions.
    struct Trace(Vec<Pid>);

    impl Trace {
        fn count(&self, pid: Pid) -> usize {
            self.0.iter().filter(|p| **p == pid).count()
        }
    }

    fn ready_sched(n: u32, prio: u32) -> (Scheduler, Vec<Pid>) {
        let mut s = Scheduler::new();
        let mut pids = Vec::new();
        for _ in 0..n {
            let p = s.spawn(prio);
            s.make_ready(p).unwrap();
            pids.push(p);
        }
        (s, pids)
    }

    #[test]
    fn spawn_assigns_sequential_pids_in_new_state() {
        let mut s = Scheduler::new();
        let a = s.spawn(0);
        let b = s.spawn(0);
        assert_eq!(a.0, 1);
        assert_eq!(b.0, 2);
        assert_eq!(s.get(a).unwrap().state, State::New);
        assert!(!s.get(a).unwrap().state.is_runnable());
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn new_tasks_are_not_scheduled() {
        let mut s = Scheduler::new();
        s.spawn(0);
        assert_eq!(s.pick_next(), None);
        assert_eq!(s.runnable_count(), 0);
    }

    #[test]
    fn pick_next_round_robins_within_a_priority() {
        let (mut s, pids) = ready_sched(3, 0);
        assert_eq!(s.pick_next(), Some(pids[0]));
        assert_eq!(s.pick_next(), Some(pids[1]));
        assert_eq!(s.pick_next(), Some(pids[2]));
        assert_eq!(s.pick_next(), Some(pids[0]), "must wrap around");
        s.validate().unwrap();
    }

    #[test]
    fn higher_priority_runs_before_lower() {
        let mut s = Scheduler::new();
        let lo = s.spawn(1);
        s.make_ready(lo).unwrap();
        let hi = s.spawn(5);
        s.make_ready(hi).unwrap();

        // The single high-priority task takes every dispatch while the low one
        // stays queued: strict priority is not fair, which is why aging exists.
        let mut order = Vec::new();
        for _ in 0..4 {
            order.push(s.pick_next().unwrap());
        }
        assert!(order.iter().all(|p| *p == hi));
        assert_eq!(s.runnable_count(), 2, "lo is ready but not yet running");
        s.validate().unwrap();
    }

    #[test]
    fn high_priority_tasks_share_among_themselves() {
        let mut s = Scheduler::new();
        let lo = s.spawn(1);
        s.make_ready(lo).unwrap();
        let h1 = s.spawn(5);
        let h2 = s.spawn(5);
        s.make_ready(h1).unwrap();
        s.make_ready(h2).unwrap();

        let mut order = Vec::new();
        for _ in 0..4 {
            order.push(s.pick_next().unwrap());
        }
        assert_eq!(
            order,
            vec![h1, h2, h1, h2],
            "equal priority must round-robin"
        );
        s.validate().unwrap();
    }

    #[test]
    fn blocked_tasks_are_skipped() {
        let (mut s, pids) = ready_sched(3, 0);
        s.block(pids[1], BlockReason::Io).unwrap();

        assert_eq!(s.pick_next(), Some(pids[0]));
        assert_eq!(s.pick_next(), Some(pids[2]));
        assert_eq!(s.pick_next(), Some(pids[0]));
        assert_eq!(s.runnable_count(), 2);
        assert_eq!(s.get(pids[1]).unwrap().blocked_on, Some(BlockReason::Io));
        s.validate().unwrap();
    }

    #[test]
    fn re_readying_a_blocked_task_puts_it_back() {
        let (mut s, pids) = ready_sched(2, 0);
        s.block(pids[0], BlockReason::Io).unwrap();
        s.make_ready(pids[0]).unwrap();

        let mut seen = Vec::new();
        for _ in 0..2 {
            seen.push(s.pick_next().unwrap());
        }
        assert!(seen.contains(&pids[0]));
        assert_eq!(s.get(pids[0]).unwrap().blocked_on, None);
        s.validate().unwrap();
    }

    #[test]
    fn quantum_expires_after_the_configured_ticks() {
        let (mut s, _) = ready_sched(1, 0);
        s.quantum = 3;
        s.pick_next().unwrap();

        assert!(!s.tick().unwrap(), "tick 1 of 3");
        assert!(!s.tick().unwrap(), "tick 2 of 3");
        assert!(s.tick().unwrap(), "tick 3 must request a reschedule");
    }

    #[test]
    fn clock_advances_one_tick_per_call() {
        let (mut s, _) = ready_sched(1, 0);
        assert_eq!(s.clock(), 0);
        s.pick_next();
        for expected in 1..=5 {
            s.tick().unwrap();
            assert_eq!(s.clock(), expected);
        }
    }

    #[test]
    fn a_blocked_task_stops_consuming_quantum() {
        let (mut s, pids) = ready_sched(1, 0);
        s.pick_next().unwrap();
        s.block(pids[0], BlockReason::Io).unwrap();

        for _ in 0..5 {
            assert!(!s.tick().unwrap(), "a blocked task must not expire");
        }
    }

    #[test]
    fn tick_without_a_current_task_is_an_error() {
        let mut s = Scheduler::new();
        assert_eq!(s.tick(), Err(SchedError::NoPidAllocated));
    }

    #[test]
    fn exited_tasks_never_run_again() {
        let (mut s, pids) = ready_sched(3, 0);
        s.exit(pids[0]).unwrap();
        s.exit(pids[1]).unwrap();

        assert_eq!(s.runnable_count(), 1);
        for _ in 0..4 {
            assert_eq!(s.pick_next(), Some(pids[2]));
        }
        assert!(s.get(pids[0]).unwrap().state.is_terminal());
    }

    #[test]
    fn double_exit_is_rejected() {
        let (mut s, pids) = ready_sched(1, 0);
        s.exit(pids[0]).unwrap();
        assert_eq!(s.exit(pids[0]), Err(SchedError::InvalidTransition));
    }

    #[test]
    fn exiting_the_current_task_clears_it() {
        let (mut s, pids) = ready_sched(2, 0);
        s.pick_next().unwrap();
        assert_eq!(s.current(), Some(pids[0]));
        s.exit(pids[0]).unwrap();
        assert_eq!(s.current(), None);
    }

    #[test]
    fn set_priority_moves_a_runnable_task_between_queues() {
        let (mut s, pids) = ready_sched(1, 0);
        s.set_priority(pids[0], 9).unwrap();
        assert_eq!(s.queue_len(0), 0);
        assert_eq!(s.queue_len(9), 1);
        assert_eq!(s.pick_next(), Some(pids[0]));
        s.validate().unwrap();
    }

    #[test]
    fn set_priority_on_a_blocked_task_keeps_it_blocked() {
        let (mut s, pids) = ready_sched(1, 0);
        s.block(pids[0], BlockReason::Futex).unwrap();
        s.set_priority(pids[0], 9).unwrap();
        assert_eq!(s.queue_len(0), 0);
        assert_eq!(s.queue_len(9), 0, "blocked tasks belong to no queue");
        assert_eq!(s.pick_next(), None);
        s.validate().unwrap();
    }

    #[test]
    fn unknown_pids_are_rejected_everywhere() {
        let mut s = Scheduler::new();
        let ghost = Pid(999);
        assert_eq!(s.get(ghost), Err(SchedError::NoSuchPid));
        assert_eq!(s.make_ready(ghost), Err(SchedError::NoSuchPid));
        assert_eq!(s.block(ghost, BlockReason::Io), Err(SchedError::NoSuchPid));
        assert_eq!(s.exit(ghost), Err(SchedError::NoSuchPid));
        assert_eq!(s.set_priority(ghost, 1), Err(SchedError::NoSuchPid));
    }

    #[test]
    fn sleepers_wake_when_the_clock_passes_their_deadline() {
        let (mut s, pids) = ready_sched(1, 0);
        s.block(pids[0], BlockReason::Sleep).unwrap();
        s.get_mut(pids[0]).unwrap().quantum_left = 10;

        assert!(s.wake_sleepers(5).is_empty(), "not due yet");
        assert_eq!(s.wake_sleepers(10).len(), 1);
        assert_eq!(s.get(pids[0]).unwrap().state, State::Ready);
    }

    #[test]
    fn stopped_tasks_are_not_runnable() {
        let (mut s, pids) = ready_sched(2, 0);
        s.stop(pids[0]).unwrap();
        assert_eq!(s.get(pids[0]).unwrap().state, State::Stopped);
        assert_eq!(s.runnable_count(), 1);
        assert_eq!(s.pick_next(), Some(pids[1]));
    }

    #[test]
    fn run_until_idle_terminates_when_nothing_is_runnable() {
        let (mut s, _) = ready_sched(2, 0);
        for pid in s.tasks.keys().copied().collect::<Vec<_>>() {
            s.exit(Pid(pid)).unwrap();
        }
        let mut t = Trace(Vec::new());
        s.run_until_idle(100, |p| t.0.push(p));
        assert!(t.0.is_empty());
    }

    #[test]
    fn fairness_is_exact_under_equal_priority() {
        let (mut s, _) = ready_sched(4, 0);
        let mut t = Trace(Vec::new());
        s.run_until_idle(40, |p| t.0.push(p));

        assert_eq!(t.0.len(), 40);
        for pid in 1..=4u32 {
            assert_eq!(t.count(Pid(pid)), 10, "pid {pid} starved or hogged");
        }
        s.validate().unwrap();
    }

    #[test]
    fn a_low_priority_task_is_never_starved_forever() {
        // One low-priority task against eight high-priority ones. Without
        // aging this task would never run.
        let mut s = Scheduler::new();
        let low = s.spawn(0);
        s.make_ready(low).unwrap();
        for _ in 0..8 {
            let h = s.spawn(10);
            s.make_ready(h).unwrap();
        }

        let mut t = Trace(Vec::new());
        s.run_until_idle(300, |p| t.0.push(p));
        assert!(
            t.count(low) > 0,
            "aging must eventually promote the starved task"
        );
    }

    #[test]
    fn aging_promotes_a_starved_task_past_higher_priorities() {
        let mut s = Scheduler::new();
        let low = s.spawn(0);
        s.make_ready(low).unwrap();
        let hi = s.spawn(1);
        s.make_ready(hi).unwrap();

        // One point of priority is worth AGING_PERIOD ticks of waiting.
        assert_eq!(s.effective_priority(low), Some(0));
        assert_eq!(s.effective_priority(hi), Some(1));

        // Let the high-priority task run until `low` has aged past it.
        let mut found = false;
        for _ in 0..(Scheduler::AGING_PERIOD * 2) {
            s.pick_next().unwrap();
            s.tick().unwrap();
            if s.get(low).unwrap().ran > 0 {
                found = true;
                break;
            }
        }
        assert!(found, "low-priority task never got promoted");
    }

    #[test]
    fn waiting_resets_when_a_task_is_dispatched() {
        let mut s = Scheduler::new();
        let a = s.spawn(0);
        let b = s.spawn(0);
        s.make_ready(a).unwrap();
        s.make_ready(b).unwrap();

        s.pick_next().unwrap();
        s.tick().unwrap();
        // Exactly one of them waited.
        let waited_a = s.get(a).unwrap().waited;
        let waited_b = s.get(b).unwrap().waited;
        assert_eq!(waited_a + waited_b, 1);
        assert_eq!(waited_a.max(waited_b), 1);
    }

    #[test]
    fn effective_priority_is_none_for_non_runnable_tasks() {
        let mut s = Scheduler::new();
        let a = s.spawn(3);
        assert_eq!(s.effective_priority(a), None, "New is not runnable");
        s.make_ready(a).unwrap();
        assert_eq!(s.effective_priority(a), Some(3));
        s.block(a, BlockReason::Io).unwrap();
        assert_eq!(s.effective_priority(a), None);
        assert_eq!(s.effective_priority(Pid(999)), None);
    }

    #[test]
    fn blocking_stops_a_task_accruing_wait_time() {
        let mut s = Scheduler::new();
        let a = s.spawn(0);
        let b = s.spawn(0);
        s.make_ready(a).unwrap();
        s.make_ready(b).unwrap();
        s.pick_next().unwrap();
        s.tick().unwrap();

        // `b` already accrued a wait tick while runnable, so freeze its count
        // at the moment of blocking and require it to stay there.
        s.block(b, BlockReason::Io).unwrap();
        let at_block = s.get(b).unwrap().waited;
        for _ in 0..50 {
            s.pick_next().unwrap();
            s.tick().unwrap();
        }
        assert_eq!(
            s.get(b).unwrap().waited,
            at_block,
            "a blocked task must not accrue further wait time"
        );
        assert_eq!(s.get(b).unwrap().ran, 0, "a blocked task must not run");
    }

    #[test]
    fn workload_never_starves_under_a_burst_of_sleepers() {
        let (mut s, pids) = ready_sched(2, 0);
        // A task that repeatedly blocks and wakes.
        let mut t = Trace(Vec::new());
        for i in 0..30 {
            let p = s.pick_next().expect("a task must always be runnable");
            t.0.push(p);
            s.tick().unwrap();
            if i % 3 == 0 {
                s.block(p, BlockReason::Io).unwrap();
                s.make_ready(p).unwrap();
            }
        }
        assert_eq!(t.count(pids[0]) + t.count(pids[1]), 30);
        s.validate().unwrap();
    }

    #[test]
    fn validate_catches_a_corrupted_queue() {
        let (mut s, pids) = ready_sched(2, 0);
        s.validate().unwrap();
        // Inject a duplicate by hand; the scheduler must notice.
        s.queues.get_mut(&0).unwrap().push(pids[0]);
        assert_eq!(s.validate(), Err(SchedError::QueueCorrupt));
    }

    #[test]
    fn validate_catches_a_stale_queue_entry() {
        let (mut s, pids) = ready_sched(2, 0);
        s.block(pids[0], BlockReason::Io).ok();
        s.make_ready(pids[0]).unwrap();
        // Now block it directly in the task table, leaving the queue entry.
        s.get_mut(pids[0]).unwrap().state = State::Blocked;
        assert_eq!(s.validate(), Err(SchedError::QueueCorrupt));
    }

    #[test]
    fn queue_len_reflects_runnable_work() {
        let (mut s, pids) = ready_sched(3, 2);
        assert_eq!(s.queue_len(2), 3);
        assert_eq!(s.queue_len(7), 0);
        s.block(pids[0], BlockReason::Io).unwrap();
        assert_eq!(s.queue_len(2), 2);
    }
}
