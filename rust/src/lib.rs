#![forbid(unsafe_code)]

pub mod hardware_identity;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Send,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Handbook,
    ScratchNote,
    SimulationInbox,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Session {
    Alice,
    Bob,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Normal,
    Degraded,
    Quarantined,
    SafeMode,
    RecoveryRequired,
}
#[derive(Clone, Debug)]
pub struct Policy {
    pub lease_ms: u64,
    pub intervention_ms: u64,
    pub max_requests: usize,
    pub max_permits: usize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            lease_ms: 10_000,
            intervention_ms: 1_000,
            max_requests: 128,
            max_permits: 32,
        }
    }
}
impl Policy {
    fn validate(&self) -> Result<(), &'static str> {
        if !(1..=60_000).contains(&self.lease_ms)
            || self.intervention_ms == 0
            || self.intervention_ms >= self.lease_ms
            || !(1..=4096).contains(&self.max_requests)
            || !(1..=256).contains(&self.max_permits)
        {
            return Err("invalid_policy");
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub session: Session,
    pub action: Action,
    pub resource: Resource,
    pub content: String,
    pub uncertainty: f64,
    pub permit: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: &'static str,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub state: State,
    pub generation: u64,
    pub held_sessions: usize,
    pub isolated_sessions: usize,
    pub pending_windows: usize,
    pub effects: usize,
    pub permits: usize,
    pub lease_remaining_ms: u64,
}
#[derive(Clone, Debug)]
pub struct Evidence {
    pub sequence: usize,
    pub time_ms: u64,
    pub event: &'static str,
    pub request_id: Option<String>,
    pub reason: &'static str,
}
pub trait EvidenceSink: Send {
    fn append(&mut self, event: Evidence) -> Result<(), &'static str>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub id: String,
    pub session: Session,
    pub action: Action,
    pub resource: Resource,
    pub content: String,
}
pub trait Adapter: Send {
    fn execute(&mut self, request: &Request) -> Result<(), &'static str>;
    fn inspect(&self, id: &str) -> Option<Observation>;
    fn clean(&self, session: Session, incident: u64) -> bool;
}

#[derive(Clone)]
pub struct MemoryEvidence {
    rows: Arc<Mutex<Vec<Evidence>>>,
    capacity: usize,
}
impl MemoryEvidence {
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: Arc::new(Mutex::new(Vec::new())),
            capacity,
        }
    }
    pub fn rows(&self) -> Vec<Evidence> {
        self.rows.lock().expect("evidence mutex poisoned").clone()
    }
}
impl EvidenceSink for MemoryEvidence {
    fn append(&mut self, e: Evidence) -> Result<(), &'static str> {
        let mut rows = self.rows.lock().map_err(|_| "evidence_poisoned")?;
        if rows.len() >= self.capacity {
            return Err("evidence_full");
        }
        rows.push(e);
        Ok(())
    }
}
#[derive(Clone, Default)]
pub struct SimulatedAdapter {
    inner: Arc<Mutex<SimulatedState>>,
}
#[derive(Default)]
struct SimulatedState {
    effects: BTreeMap<String, Observation>,
    clean: BTreeSet<(u8, u64)>,
}
impl SimulatedAdapter {
    // This belongs only to the trusted fixture. Never expose it through the worker protocol.
    #[cfg(feature = "test-fixtures")]
    pub fn mark_clean(&self, session: Session, incident: u64) {
        self.inner
            .lock()
            .expect("adapter poisoned")
            .clean
            .insert((session as u8, incident));
    }
}
impl Adapter for SimulatedAdapter {
    fn execute(&mut self, r: &Request) -> Result<(), &'static str> {
        self.inner
            .lock()
            .map_err(|_| "adapter_poisoned")?
            .effects
            .insert(
                r.id.clone(),
                Observation {
                    id: r.id.clone(),
                    session: r.session,
                    action: r.action,
                    resource: r.resource,
                    content: r.content.clone(),
                },
            );
        Ok(())
    }
    fn inspect(&self, id: &str) -> Option<Observation> {
        self.inner.lock().ok()?.effects.get(id).cloned()
    }
    fn clean(&self, session: Session, incident: u64) -> bool {
        self.inner
            .lock()
            .map(|s| s.clean.contains(&(session as u8, incident)))
            .unwrap_or(false)
    }
}
struct Permit {
    session: Session,
    action: Action,
    resource: Resource,
    generation: u64,
    expires: u64,
    used: bool,
}
struct Hold {
    session: Session,
    generation: u64,
    incident: u64,
    isolated: bool,
    deadline: Option<u64>,
}
struct Core {
    policy: Policy,
    start: Instant,
    offset: u64,
    state: State,
    generation: u64,
    instance: String,
    deadline: u64,
    seen: BTreeSet<String>,
    permits: BTreeMap<String, Permit>,
    holds: Vec<Hold>,
    next_incident: u64,
    effects: usize,
    sequence: usize,
    sink: Box<dyn EvidenceSink>,
    adapter: Box<dyn Adapter>,
}
impl Core {
    fn now(&self) -> u64 {
        (self.start.elapsed().as_millis().min(u64::MAX as u128) as u64).saturating_add(self.offset)
    }
    fn record(
        &mut self,
        event: &'static str,
        id: Option<&str>,
        reason: &'static str,
    ) -> Result<(), &'static str> {
        let next = self.sequence.checked_add(1).ok_or("sequence_exhausted")?;
        self.sink.append(Evidence {
            sequence: next,
            time_ms: self.now(),
            event,
            request_id: id.map(str::to_string),
            reason,
        })?;
        self.sequence = next;
        Ok(())
    }
    fn revoke(&mut self, reason: &'static str) {
        // Expire authority before attempting evidence storage.
        self.deadline = 0;
        self.permits.clear();
        for h in &mut self.holds {
            h.deadline = None;
        }
        for state in [
            State::Degraded,
            State::Quarantined,
            State::SafeMode,
            State::RecoveryRequired,
        ] {
            self.state = state;
            let _ = self.record("self_containment", None, reason);
        }
    }
    fn tick(&mut self) -> Result<(), &'static str> {
        if self.state == State::Normal && self.now() >= self.deadline {
            self.revoke("lease_expired");
        }
        if self.state != State::Normal {
            return Ok(());
        }
        let now = self.now();
        for index in 0..self.holds.len() {
            if self.holds[index].deadline.is_some_and(|d| now >= d) {
                self.record("isolation_intent", None, "window_expired")?;
                self.holds[index].isolated = true;
                self.holds[index].deadline = None;
                self.record("isolation_reconciliation", None, "simulated_isolation")?;
            }
        }
        Ok(())
    }
    fn lease(&mut self) -> Result<(), &'static str> {
        self.tick()?;
        if self.state != State::Normal {
            return Err("authority_expired");
        }
        Ok(())
    }
    fn hold(
        &mut self,
        session: Session,
        isolated: bool,
        pending: bool,
    ) -> Result<(), &'static str> {
        if self.holds.iter().any(|h| h.session == session) {
            return Ok(());
        }
        self.next_incident = self
            .next_incident
            .checked_add(1)
            .ok_or("incident_exhausted")?;
        self.holds.push(Hold {
            session,
            generation: self.generation,
            incident: self.next_incident,
            isolated,
            deadline: pending.then(|| self.now().saturating_add(self.policy.intervention_ms)),
        });
        Ok(())
    }
    fn deny(&mut self, id: &str, reason: &'static str) -> Result<Decision, &'static str> {
        self.record("action_denied", Some(id), reason)?;
        Ok(Decision {
            allowed: false,
            reason,
        })
    }
    fn action(&mut self, generation: u64, r: Request) -> Result<Decision, &'static str> {
        self.lease()?;
        if generation != self.generation {
            return self.deny(&r.id, "former_worker");
        }
        if r.id.is_empty()
            || r.id.len() > 128
            || r.content.len() > 8192
            || r.permit.as_ref().is_some_and(|p| p.len() > 128)
        {
            return self.deny("invalid", "invalid_request");
        }
        if !r.uncertainty.is_finite() || !(0.0..=1.0).contains(&r.uncertainty) {
            return self.deny(&r.id, "invalid_uncertainty");
        }
        if !matches!(
            (r.action, r.resource),
            (Action::Read, Resource::Handbook)
                | (Action::Write, Resource::ScratchNote)
                | (Action::Send, Resource::SimulationInbox)
        ) {
            return self.deny(&r.id, "outside_authority");
        }
        if self.seen.contains(&r.id) {
            return self.deny(&r.id, "request_replay");
        }
        if self.seen.len() >= self.policy.max_requests {
            return self.deny(&r.id, "capacity_reached");
        }
        self.seen.insert(r.id.clone());
        if self.holds.iter().any(|h| h.session == r.session) {
            return self.deny(&r.id, "session_held");
        }
        if r.uncertainty > 0.0 {
            return self.deny(&r.id, "uncertainty");
        }
        if r.action == Action::Send && r.content.contains("SENTRY_SYNTHETIC_SECRET_01") {
            self.record("containment_intent", Some(&r.id), "synthetic_tripwire")?;
            self.hold(r.session, false, true)?;
            self.record("containment_reconciliation", Some(&r.id), "session_held")?;
            return self.deny(&r.id, "synthetic_tripwire");
        }
        if r.action != Action::Read {
            let now = self.now();
            let valid = r
                .permit
                .as_ref()
                .and_then(|id| self.permits.get(id))
                .is_some_and(|p| {
                    !p.used
                        && p.generation == generation
                        && p.session == r.session
                        && p.action == r.action
                        && p.resource == r.resource
                        && now < p.expires
                });
            if !valid {
                return self.deny(&r.id, "permission_required");
            }
        }
        self.record("action_intent", Some(&r.id), "preauthorized")?;
        if r.action != Action::Read {
            if let Some(p) = r.permit.as_ref().and_then(|id| self.permits.get_mut(id)) {
                p.used = true;
            }
        }
        self.lease()?;
        let execution = self.adapter.execute(&r);
        let observed = self.adapter.inspect(&r.id);
        let expected = Observation {
            id: r.id.clone(),
            session: r.session,
            action: r.action,
            resource: r.resource,
            content: r.content.clone(),
        };
        let verified =
            execution.is_ok() && observed.as_ref() == Some(&expected) && self.now() < self.deadline;
        if observed.is_some() {
            self.effects += 1;
        }
        let reconciliation = self.record(
            "action_reconciliation",
            Some(&r.id),
            if verified {
                "simulated_postcondition_verified"
            } else {
                "outcome_unknown_or_mismatch"
            },
        );
        if !verified || reconciliation.is_err() {
            let _ = self.hold(r.session, true, false);
            self.revoke("execution_or_evidence_failure");
            let _ = self.record(
                "emergency_reconciliation",
                Some(&r.id),
                "access_held_outcome_untrusted",
            );
            return Err("execution_or_evidence_failure");
        }
        Ok(Decision {
            allowed: true,
            reason: "allowed",
        })
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            generation: self.generation,
            held_sessions: self.holds.len(),
            isolated_sessions: self.holds.iter().filter(|h| h.isolated).count(),
            pending_windows: self.holds.iter().filter(|h| h.deadline.is_some()).count(),
            effects: self.effects,
            permits: self.permits.len(),
            lease_remaining_ms: self.deadline.saturating_sub(self.now()),
        }
    }
}

/// Trusted embedding API. Do not pass Supervisor, sinks or adapters to an untrusted worker.
pub struct Supervisor {
    core: Arc<Mutex<Core>>,
}
/// Only the supervisor can construct a worker port. Its generation cannot be edited externally.
///
/// ```compile_fail
/// use sentry_external_testing::Worker;
/// fn expand_authority(worker: Worker) { worker.grant(); }
/// ```
///
/// ```compile_fail
/// use sentry_external_testing::Worker;
/// fn change_generation(worker: &mut Worker) { worker.generation = 100; }
/// ```
#[derive(Clone)]
pub struct Worker {
    core: Arc<Mutex<Core>>,
    generation: u64,
}
pub fn controller(
    policy: Policy,
    sink: Box<dyn EvidenceSink>,
    adapter: Box<dyn Adapter>,
) -> Result<Supervisor, &'static str> {
    policy.validate()?;
    let mut core = Core {
        policy,
        start: Instant::now(),
        offset: 0,
        state: State::RecoveryRequired,
        generation: 0,
        instance: String::new(),
        deadline: 0,
        seen: BTreeSet::new(),
        permits: BTreeMap::new(),
        holds: Vec::new(),
        next_incident: 0,
        effects: 0,
        sequence: 0,
        sink,
        adapter,
    };
    core.record("boot", None, "fixed_authority")?;
    Ok(Supervisor {
        core: Arc::new(Mutex::new(core)),
    })
}
impl Supervisor {
    pub(crate) fn hardware_failure(&self, reason: &'static str) {
        if let Ok(mut core) = self.core.lock() {
            core.revoke(reason);
            let _ = core.record("hardware_verification_reconciliation", None, reason);
        }
    }
    pub fn recover(
        &self,
        instance: &str,
        generation: u64,
        integrity: bool,
    ) -> Result<Worker, &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if !integrity {
            c.revoke("integrity_failure");
            return Err("invalid_attestation");
        }
        if c.tick().is_err() {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        if c.state != State::RecoveryRequired
            || instance.is_empty()
            || instance.len() > 128
            || instance == c.instance
            || generation <= c.generation
        {
            return Err("clean_replacement_required");
        }
        if c.record("recovery_intent", None, "trusted_fixture_attestation")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        c.instance = instance.to_string();
        c.generation = generation;
        c.deadline = c.now().saturating_add(c.policy.lease_ms);
        c.state = State::Normal;
        if c.record("recovery_reconciliation", None, "holds_preserved")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        Ok(Worker {
            core: self.core.clone(),
            generation,
        })
    }
    pub fn attest(
        &self,
        instance: &str,
        generation: u64,
        integrity: bool,
    ) -> Result<(), &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if !integrity {
            c.revoke("integrity_failure");
            return Err("invalid_attestation");
        }
        if let Err(e) = c.lease() {
            if e != "authority_expired" {
                c.revoke("evidence_failure");
            }
            return Err(e);
        }
        if instance != c.instance || generation != c.generation {
            return Err("instance_mismatch");
        }
        if c.record("attestation_intent", None, "trusted_fixture_attestation")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        c.deadline = c.now().saturating_add(c.policy.lease_ms);
        if c.record("attestation_reconciliation", None, "lease_renewed")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        Ok(())
    }
    pub fn grant(
        &self,
        id: &str,
        session: Session,
        action: Action,
        resource: Resource,
        ttl_ms: u64,
    ) -> Result<(), &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if let Err(e) = c.lease() {
            if e != "authority_expired" {
                c.revoke("evidence_failure");
            }
            return Err(e);
        }
        if !matches!(
            (action, resource),
            (Action::Write, Resource::ScratchNote) | (Action::Send, Resource::SimulationInbox)
        ) || ttl_ms == 0
            || ttl_ms > c.policy.lease_ms
            || id.is_empty()
            || id.len() > 128
        {
            return Err("outside_authority");
        }
        if c.permits.contains_key(id) {
            return Err("duplicate_permit");
        }
        if c.permits.len() >= c.policy.max_permits {
            return Err("capacity_reached");
        }
        if c.record("permit_intent", Some(id), "human_fixture_grant")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        let permit = Permit {
            session,
            action,
            resource,
            generation: c.generation,
            expires: c.now().saturating_add(ttl_ms).min(c.deadline),
            used: false,
        };
        c.permits.insert(id.to_string(), permit);
        if c.record("permit_reconciliation", Some(id), "one_use_issued")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        Ok(())
    }
    pub fn cancel_escalation(&self, session: Session) -> Result<(), &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if let Err(e) = c.lease() {
            if e != "authority_expired" {
                c.revoke("evidence_failure");
            }
            return Err(e);
        }
        let index = c
            .holds
            .iter()
            .position(|h| h.session == session && h.deadline.is_some())
            .ok_or("no_open_window")?;
        if c.record("window_cancel_intent", None, "human_fixture_override")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        c.holds[index].deadline = None;
        if c.record("window_cancel_reconciliation", None, "hold_preserved")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        Ok(())
    }
    pub fn release_hold(&self, session: Session) -> Result<(), &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if let Err(e) = c.lease() {
            if e != "authority_expired" {
                c.revoke("evidence_failure");
            }
            return Err(e);
        }
        let index = c
            .holds
            .iter()
            .position(|h| h.session == session)
            .ok_or("no_hold")?;
        let h = &c.holds[index];
        if c.generation <= h.generation || !c.adapter.clean(session, h.incident) {
            return Err("recovery_not_verified");
        }
        if c.record("hold_release_intent", None, "human_fixture_release")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        c.holds.remove(index);
        if c.record("hold_release_reconciliation", None, "clean_simulated_path")
            .is_err()
        {
            c.revoke("evidence_failure");
            return Err("evidence_failure");
        }
        Ok(())
    }
    #[cfg(feature = "test-fixtures")]
    pub fn advance_fixture_clock(&self, ms: u64) -> Result<(), &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        c.offset = c.offset.checked_add(ms).ok_or("clock_overflow")?;
        if let Err(e) = c.tick() {
            c.revoke("evidence_failure");
            return Err(e);
        }
        Ok(())
    }
    #[cfg(feature = "test-fixtures")]
    pub fn incident(&self, session: Session) -> Option<u64> {
        self.core
            .lock()
            .ok()?
            .holds
            .iter()
            .find(|h| h.session == session)
            .map(|h| h.incident)
    }
}
impl Worker {
    pub fn reject_input(&self, reason: &'static str) -> Result<Decision, &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        let result = c.deny("protocol_input", reason);
        if result.is_err() {
            c.revoke("evidence_failure");
        }
        result
    }
    pub fn propose(&self, request: Request) -> Result<Decision, &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        let result = c.action(self.generation, request);
        if let Err(e) = result {
            if e != "authority_expired" {
                c.revoke("evidence_or_execution_failure");
            }
        }
        result
    }
    pub fn status(&self) -> Result<Snapshot, &'static str> {
        let mut c = self.core.lock().map_err(|_| "controller_poisoned")?;
        if c.tick().is_err() {
            c.revoke("evidence_failure");
        }
        Ok(c.snapshot())
    }
}
