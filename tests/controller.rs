#![cfg(feature = "test-fixtures")]
use sentry_external_testing::*;
use std::sync::{Arc, Mutex};
fn fixture() -> (Supervisor, Worker, MemoryEvidence, SimulatedAdapter) {
    let sink = MemoryEvidence::new(4096);
    let adapter = SimulatedAdapter::default();
    let s = controller(
        Policy::default(),
        Box::new(sink.clone()),
        Box::new(adapter.clone()),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    (s, w, sink, adapter)
}
fn read(id: &str) -> Request {
    Request {
        id: id.into(),
        session: Session::Alice,
        action: Action::Read,
        resource: Resource::Handbook,
        content: String::new(),
        uncertainty: 0.0,
        permit: None,
    }
}
fn send(id: &str, permit: Option<&str>) -> Request {
    Request {
        action: Action::Send,
        resource: Resource::SimulationInbox,
        permit: permit.map(str::to_string),
        ..read(id)
    }
}
fn leak(w: &Worker, id: &str) {
    let mut r = send(id, None);
    r.content = "SENTRY_SYNTHETIC_SECRET_01".into();
    assert_eq!(w.propose(r).unwrap().reason, "synthetic_tripwire");
}
#[test]
fn baseline_scope_and_no_new_powers() {
    let (s, w, _, _) = fixture();
    assert!(w.propose(read("a")).unwrap().allowed);
    assert_eq!(
        w.propose(Request {
            resource: Resource::SimulationInbox,
            ..read("b")
        })
        .unwrap()
        .reason,
        "outside_authority"
    );
    assert_eq!(
        s.grant("p", Session::Alice, Action::Send, Resource::Handbook, 5),
        Err("outside_authority")
    );
}
#[test]
fn permits_are_scoped_single_use() {
    let (s, w, _, _) = fixture();
    s.grant(
        "p",
        Session::Alice,
        Action::Send,
        Resource::SimulationInbox,
        500,
    )
    .unwrap();
    assert_eq!(
        w.propose(Request {
            session: Session::Bob,
            ..send("wrong", Some("p"))
        })
        .unwrap()
        .reason,
        "permission_required"
    );
    assert!(w.propose(send("good", Some("p"))).unwrap().allowed);
    assert_eq!(
        w.propose(send("reuse", Some("p"))).unwrap().reason,
        "permission_required"
    );
}
#[test]
fn permit_expiry_and_request_replay() {
    let (s, w, _, _) = fixture();
    s.grant(
        "p",
        Session::Alice,
        Action::Send,
        Resource::SimulationInbox,
        500,
    )
    .unwrap();
    s.advance_fixture_clock(501).unwrap();
    assert_eq!(
        w.propose(send("expired", Some("p"))).unwrap().reason,
        "permission_required"
    );
    w.propose(read("r")).unwrap();
    assert_eq!(w.propose(read("r")).unwrap().reason, "request_replay");
}
#[test]
fn uncertainty_never_expands_authority() {
    let (_, w, _, _) = fixture();
    for (n, u) in [0.01, 0.5, 1.0].iter().enumerate() {
        assert_eq!(
            w.propose(Request {
                uncertainty: *u,
                ..read(&format!("u{n}"))
            })
            .unwrap()
            .reason,
            "uncertainty"
        );
    }
    for u in [f64::NAN, f64::INFINITY, -1.0] {
        assert_eq!(
            w.propose(Request {
                uncertainty: u,
                ..read("bad")
            })
            .unwrap()
            .reason,
            "invalid_uncertainty"
        );
    }
    assert_eq!(w.status().unwrap().effects, 0);
}
#[test]
fn tripwire_preserves_legitimate_session() {
    let (s, w, _, _) = fixture();
    leak(&w, "leak");
    assert_eq!(w.propose(read("held")).unwrap().reason, "session_held");
    assert!(
        w.propose(Request {
            session: Session::Bob,
            ..read("bob")
        })
        .unwrap()
        .allowed
    );
    s.advance_fixture_clock(1001).unwrap();
    assert_eq!(w.status().unwrap().isolated_sessions, 1);
}
#[test]
fn intervention_cancel_does_not_release_access() {
    let (s, w, _, _) = fixture();
    leak(&w, "leak");
    s.cancel_escalation(Session::Alice).unwrap();
    s.advance_fixture_clock(1001).unwrap();
    assert_eq!(w.status().unwrap().held_sessions, 1);
    assert_eq!(w.status().unwrap().isolated_sessions, 0);
    assert_eq!(s.cancel_escalation(Session::Alice), Err("no_open_window"));
}
#[test]
fn expired_window_cannot_be_cancelled() {
    let (s, w, _, _) = fixture();
    leak(&w, "leak");
    s.advance_fixture_clock(1001).unwrap();
    assert_eq!(s.cancel_escalation(Session::Alice), Err("no_open_window"));
}
#[test]
fn deadman_revokes_before_later_execution() {
    let (s, w, sink, _) = fixture();
    s.advance_fixture_clock(10000).unwrap();
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
    assert_eq!(w.propose(read("expired")), Err("authority_expired"));
    assert_eq!(
        sink.rows()
            .iter()
            .filter(|r| r.event == "self_containment")
            .count(),
        4
    );
}
#[test]
fn integrity_failure_cannot_be_renewed() {
    let (s, w, _, _) = fixture();
    assert_eq!(s.attest("first", 1, false), Err("invalid_attestation"));
    assert_eq!(s.attest("first", 1, true), Err("authority_expired"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn wrong_instance_cannot_attest() {
    let (s, w, _, _) = fixture();
    assert_eq!(s.attest("wrong", 1, true), Err("instance_mismatch"));
    assert_eq!(w.status().unwrap().generation, 1);
}
#[test]
fn former_worker_cannot_regain_authority() {
    let (s, w, _, _) = fixture();
    s.advance_fixture_clock(10000).unwrap();
    let new = s.recover("clean", 2, true).unwrap();
    assert_eq!(w.propose(read("old")).unwrap().reason, "former_worker");
    assert!(new.propose(read("new")).unwrap().allowed);
}
#[test]
fn recovery_requires_new_identity_and_generation() {
    let (s, _, _, _) = fixture();
    s.advance_fixture_clock(10000).unwrap();
    assert!(s.recover("first", 2, true).is_err());
    assert!(s.recover("new", 1, true).is_err());
    assert!(s.recover("new", 2, false).is_err());
}
#[test]
fn recovery_preserves_holds_and_needs_fresh_health() {
    let (s, w, _, adapter) = fixture();
    leak(&w, "leak");
    let incident = s.incident(Session::Alice).unwrap();
    adapter.mark_clean(Session::Alice, incident);
    assert_eq!(s.release_hold(Session::Alice), Err("recovery_not_verified"));
    s.advance_fixture_clock(10000).unwrap();
    let new = s.recover("clean", 2, true).unwrap();
    assert_eq!(new.status().unwrap().held_sessions, 1);
    s.release_hold(Session::Alice).unwrap();
    leak(&new, "second");
    s.advance_fixture_clock(10000).unwrap();
    s.recover("clean-3", 3, true).unwrap();
    assert_eq!(s.release_hold(Session::Alice), Err("recovery_not_verified"));
}
#[test]
fn bounded_requests_keep_status_available() {
    let (_, w, _, _) = fixture();
    for i in 0..128 {
        assert!(w.propose(read(&format!("r{i}"))).unwrap().allowed);
    }
    assert_eq!(
        w.propose(read("overflow")).unwrap().reason,
        "capacity_reached"
    );
    assert_eq!(w.status().unwrap().state, State::Normal);
}
#[test]
fn policy_is_copied_and_rejects_invalid_timing() {
    let p = Policy {
        lease_ms: 1,
        ..Policy::default()
    };
    assert!(controller(
        p,
        Box::new(MemoryEvidence::new(32)),
        Box::new(SimulatedAdapter::default())
    )
    .is_err());
}
#[test]
fn concurrent_permission_reuse_has_one_effect() {
    let (s, w, _, _) = fixture();
    s.grant(
        "p",
        Session::Alice,
        Action::Send,
        Resource::SimulationInbox,
        500,
    )
    .unwrap();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let w = w.clone();
            std::thread::spawn(move || {
                w.propose(send(&format!("c{i}"), Some("p")))
                    .unwrap()
                    .allowed
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter(|t| t.thread().id() != std::thread::current().id())
            .map(|t| t.join().unwrap() as usize)
            .sum::<usize>(),
        1
    );
    assert_eq!(w.status().unwrap().effects, 1);
}
struct BadAdapter;
impl Adapter for BadAdapter {
    fn execute(&mut self, _: &Request) -> Result<(), &'static str> {
        Ok(())
    }
    fn inspect(&self, _: &str) -> Option<Observation> {
        None
    }
    fn clean(&self, _: Session, _: u64) -> bool {
        false
    }
}
#[test]
fn postcondition_failure_holds_and_revokes() {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(64)),
        Box::new(BadAdapter),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    assert_eq!(
        w.propose(read("fail")),
        Err("execution_or_evidence_failure")
    );
    assert_eq!(w.status().unwrap().held_sessions, 1);
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
struct CrashAdapter {
    base: SimulatedAdapter,
}
impl Adapter for CrashAdapter {
    fn execute(&mut self, r: &Request) -> Result<(), &'static str> {
        self.base.execute(r)?;
        Err("crash_after_effect")
    }
    fn inspect(&self, id: &str) -> Option<Observation> {
        self.base.inspect(id)
    }
    fn clean(&self, _: Session, _: u64) -> bool {
        false
    }
}
#[test]
fn crash_after_effect_is_reconciled() {
    let sink = MemoryEvidence::new(64);
    let s = controller(
        Policy::default(),
        Box::new(sink.clone()),
        Box::new(CrashAdapter {
            base: SimulatedAdapter::default(),
        }),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    assert!(w.propose(read("crash")).is_err());
    assert_eq!(w.status().unwrap().effects, 1);
    assert!(sink
        .rows()
        .iter()
        .any(|e| e.event == "action_reconciliation" && e.reason == "outcome_unknown_or_mismatch"));
}
struct FaultSink {
    rows: MemoryEvidence,
    fail: Arc<Mutex<Option<&'static str>>>,
}
impl EvidenceSink for FaultSink {
    fn append(&mut self, e: Evidence) -> Result<(), &'static str> {
        let mut fail = self.fail.lock().unwrap();
        if *fail == Some(e.event) {
            *fail = None;
            return Err("ENOSPC");
        }
        self.rows.append(e)
    }
}
#[test]
fn evidence_failure_before_intent_prevents_effect() {
    let fail = Arc::new(Mutex::new(None));
    let s = controller(
        Policy::default(),
        Box::new(FaultSink {
            rows: MemoryEvidence::new(64),
            fail: fail.clone(),
        }),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    *fail.lock().unwrap() = Some("action_intent");
    assert!(w.propose(read("fail")).is_err());
    assert_eq!(w.status().unwrap().effects, 0);
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn evidence_failure_after_effect_preserves_hold() {
    let fail = Arc::new(Mutex::new(None));
    let s = controller(
        Policy::default(),
        Box::new(FaultSink {
            rows: MemoryEvidence::new(64),
            fail: fail.clone(),
        }),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    *fail.lock().unwrap() = Some("action_reconciliation");
    assert!(w.propose(read("fail")).is_err());
    assert_eq!(w.status().unwrap().effects, 1);
    assert_eq!(w.status().unwrap().held_sessions, 1);
}
#[test]
fn permit_failure_cannot_leave_authority_live() {
    let fail = Arc::new(Mutex::new(None));
    let s = controller(
        Policy::default(),
        Box::new(FaultSink {
            rows: MemoryEvidence::new(64),
            fail: fail.clone(),
        }),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    *fail.lock().unwrap() = Some("permit_reconciliation");
    assert!(s
        .grant(
            "p",
            Session::Alice,
            Action::Send,
            Resource::SimulationInbox,
            500
        )
        .is_err());
    assert_eq!(w.status().unwrap().permits, 0);
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn evidence_exhaustion_leaves_status_and_expired_gate() {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(3)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let w = s.recover("first", 1, true).unwrap();
    assert!(w.propose(read("full")).is_err());
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
