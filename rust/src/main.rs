#![forbid(unsafe_code)]
use sentry_external_testing::{
    controller, Action, MemoryEvidence, Policy, Request, Resource, Session, SimulatedAdapter,
    State, Worker,
};
use std::io::{self, BufRead, Read};

fn request(
    id: &str,
    session: Session,
    action: Action,
    resource: Resource,
    content: &str,
    permit: Option<&str>,
) -> Request {
    Request {
        id: id.into(),
        session,
        action,
        resource,
        content: content.into(),
        uncertainty: 0.0,
        permit: permit.map(str::to_string),
    }
}
fn reject(worker: &Worker, reason: &'static str) -> Result<(), &'static str> {
    let result = worker.reject_input(reason)?;
    println!("DENY\t{}", result.reason);
    Ok(())
}
fn run() -> Result<(), &'static str> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "--demo".into());
    let evidence = MemoryEvidence::new(4096);
    let adapter = SimulatedAdapter::default();
    let supervisor = controller(
        Policy::default(),
        Box::new(evidence.clone()),
        Box::new(adapter.clone()),
    )?;
    let worker = supervisor.recover("fixture-1", 1, true)?;
    if mode == "--worker-stdin" {
        // Trusted bootstrap only. No stdin command can access Supervisor or Adapter.
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let mut line = String::new();
            let size = reader
                .by_ref()
                .take(16_385)
                .read_line(&mut line)
                .map_err(|_| "invalid_input")?;
            if size == 0 {
                break;
            }
            if size > 16_384 {
                reject(&worker, "input_too_large")?;
                break;
            }
            let p: Vec<&str> = line.trim_end_matches(['\r', '\n']).split('\t').collect();
            if p == ["status"] {
                let s = worker.status()?;
                println!(
                    "STATUS\t{:?}\t{}\t{}",
                    s.state, s.generation, s.held_sessions
                );
                continue;
            }
            if p.len() != 8 || p[0] != "action" {
                reject(&worker, "worker_command_denied")?;
                continue;
            }
            let session = match p[2] {
                "alice" => Session::Alice,
                "bob" => Session::Bob,
                _ => {
                    reject(&worker, "unknown_session")?;
                    continue;
                }
            };
            let action = match p[3] {
                "read" => Action::Read,
                "write" => Action::Write,
                "send" => Action::Send,
                _ => {
                    reject(&worker, "outside_authority")?;
                    continue;
                }
            };
            let resource = match p[4] {
                "handbook" => Resource::Handbook,
                "scratch" => Resource::ScratchNote,
                "inbox" => Resource::SimulationInbox,
                _ => {
                    reject(&worker, "outside_authority")?;
                    continue;
                }
            };
            let uncertainty = match p[5].parse::<f64>() {
                Ok(v) => v,
                Err(_) => {
                    reject(&worker, "invalid_uncertainty")?;
                    continue;
                }
            };
            let mut r = request(
                p[1],
                session,
                action,
                resource,
                p[7],
                (p[6] != "-").then_some(p[6]),
            );
            r.uncertainty = uncertainty;
            match worker.propose(r) {
                Ok(d) => println!("{}\t{}", if d.allowed { "ALLOW" } else { "DENY" }, d.reason),
                Err(e) => println!("DENY\t{e}"),
            }
        }
        eprintln!(
            "Recorded: {} in-memory evidence rows; not authenticated durable evidence",
            evidence.rows().len()
        );
        return Ok(());
    }
    if mode != "--demo" {
        return Err("usage: sentry-lab --demo | --worker-stdin");
    }
    assert!(
        worker
            .propose(request(
                "read-1",
                Session::Alice,
                Action::Read,
                Resource::Handbook,
                "",
                None
            ))?
            .allowed
    );
    supervisor.grant(
        "permit-1",
        Session::Alice,
        Action::Send,
        Resource::SimulationInbox,
        500,
    )?;
    assert!(
        worker
            .propose(request(
                "send-1",
                Session::Alice,
                Action::Send,
                Resource::SimulationInbox,
                "public simulation",
                Some("permit-1")
            ))?
            .allowed
    );
    assert_eq!(
        worker
            .propose(request(
                "leak-1",
                Session::Alice,
                Action::Send,
                Resource::SimulationInbox,
                "SENTRY_SYNTHETIC_SECRET_01",
                None
            ))?
            .reason,
        "synthetic_tripwire"
    );
    assert!(
        worker
            .propose(request(
                "bob-1",
                Session::Bob,
                Action::Read,
                Resource::Handbook,
                "",
                None
            ))?
            .allowed
    );
    supervisor.advance_fixture_clock(1001)?;
    assert_eq!(worker.status()?.isolated_sessions, 1);
    supervisor.advance_fixture_clock(10000)?;
    assert_eq!(worker.status()?.state, State::RecoveryRequired);
    let clean = supervisor.recover("fixture-clean-2", 2, true)?;
    assert_eq!(clean.status()?.held_sessions, 1);
    assert_eq!(
        worker
            .propose(request(
                "old",
                Session::Bob,
                Action::Read,
                Resource::Handbook,
                "",
                None
            ))?
            .reason,
        "former_worker"
    );
    assert_eq!(
        supervisor.release_hold(Session::Alice),
        Err("recovery_not_verified")
    );
    adapter.mark_clean(
        Session::Alice,
        supervisor.incident(Session::Alice).ok_or("missing_hold")?,
    );
    supervisor.release_hold(Session::Alice)?;
    assert!(
        clean
            .propose(request(
                "restored",
                Session::Alice,
                Action::Read,
                Resource::Handbook,
                "",
                None
            ))?
            .allowed
    );
    println!("Verified: finite local Rust demo assertions passed.");
    println!(
        "Recorded: {} in-memory evidence rows.",
        evidence.rows().len()
    );
    println!("Proposed: physical TPM enrollment, persistent protected storage, OS sandbox/watchdog and live adapters.");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("SENTRY lab stopped: {e}");
        std::process::exit(1);
    }
}
