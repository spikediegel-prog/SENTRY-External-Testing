#![cfg(feature = "test-fixtures")]
use sentry_external_testing::hardware_identity::*;
use sentry_external_testing::*;

struct FixtureVerifier {
    hardware: bool,
    platform: bool,
    binding: bool,
    key: &'static str,
    profile: &'static str,
}
impl PlatformVerifier for FixtureVerifier {
    fn verify(
        &mut self,
        _: &Challenge,
        _: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        Ok(VerifiedPlatform {
            enrolled_key_id: self.key.into(),
            boot_profile: self.profile.into(),
            hardware_provenance_verified: self.hardware,
            platform_state_verified: self.platform,
            binding_verified: self.binding,
        })
    }
}
fn verifier() -> FixtureVerifier {
    FixtureVerifier {
        hardware: true,
        platform: true,
        binding: true,
        key: "enrolled-key",
        profile: "approved-boot",
    }
}
fn fixture(v: Box<dyn PlatformVerifier>) -> HardwareSupervisor {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(4096)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    HardwareSupervisor::new(
        s,
        v,
        "enrolled-key",
        "approved-boot",
        "fixed-policy-v1",
        1000,
    )
    .unwrap()
}
fn proof(n: u8) -> HardwareProof {
    HardwareProof {
        nonce: [n; 32],
        identity_signature: vec![1],
        quote: vec![2],
    }
}
fn read() -> Request {
    Request {
        id: "read".into(),
        session: Session::Alice,
        action: Action::Read,
        resource: Resource::Handbook,
        content: String::new(),
        uncertainty: 0.0,
        permit: None,
    }
}
#[test]
fn default_verifier_cannot_restore_authority() {
    let mut h = fixture(Box::new(RejectAllVerifier));
    h.challenge([1; 32], "first", 1).unwrap();
    assert_eq!(
        h.recover(proof(1)).err(),
        Some("hardware_verifier_not_configured")
    );
}
#[test]
fn finite_trusted_verifier_fixture_can_restore_existing_scope() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    assert!(w.propose(read()).unwrap().allowed);
    let r = Request {
        id: "send".into(),
        action: Action::Send,
        resource: Resource::SimulationInbox,
        ..read()
    };
    assert_eq!(w.propose(r).unwrap().reason, "permission_required");
}
#[test]
fn challenges_bind_identity_generation_and_policy() {
    let mut h = fixture(Box::new(verifier()));
    let c = h.challenge([1; 32], "first", 1).unwrap();
    assert!(String::from_utf8(c.message())
        .unwrap()
        .ends_with("instance=first\ngeneration=1\npolicy=fixed-policy-v1\n"));
    assert!(h.challenge([2; 32], "other", 2).is_err());
}
#[test]
fn expired_proof_is_not_recovery() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    h.advance_fixture_clock(1001).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("challenge_expired"));
}
#[test]
fn nonce_mismatch_consumes_exchange_and_cannot_be_retried() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    assert_eq!(h.recover(proof(2)).err(), Some("nonce_mismatch"));
    assert_eq!(h.recover(proof(1)).err(), Some("no_pending_challenge"));
    assert_eq!(
        h.challenge([1; 32], "first", 1).err(),
        Some("challenge_replay")
    );
}
#[test]
fn completed_challenge_cannot_be_replayed() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    assert_eq!(h.renew(proof(1)), Err("no_pending_challenge"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn software_provider_cannot_pass_hardware_required_policy() {
    let mut v = verifier();
    v.hardware = false;
    let mut h = fixture(Box::new(v));
    h.challenge([1; 32], "first", 1).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
}
#[test]
fn identity_signature_alone_is_not_platform_attestation() {
    let mut v = verifier();
    v.platform = false;
    let mut h = fixture(Box::new(v));
    h.challenge([1; 32], "first", 1).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
}
#[test]
fn wrong_enrolled_key_and_boot_profile_are_rejected() {
    for (key, profile) in [
        ("forged-key", "approved-boot"),
        ("enrolled-key", "changed-firmware"),
    ] {
        let mut v = verifier();
        v.key = key;
        v.profile = profile;
        let mut h = fixture(Box::new(v));
        h.challenge([1; 32], "first", 1).unwrap();
        assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
    }
}
#[test]
fn unbound_proof_is_rejected() {
    let mut v = verifier();
    v.binding = false;
    let mut h = fixture(Box::new(v));
    h.challenge([1; 32], "first", 1).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
}
#[test]
fn missing_or_oversized_evidence_is_rejected() {
    for quote in [vec![], vec![0; 65537]] {
        let mut h = fixture(Box::new(verifier()));
        h.challenge([1; 32], "first", 1).unwrap();
        let mut p = proof(1);
        p.quote = quote;
        assert_eq!(h.recover(p).err(), Some("invalid_proof_size"));
    }
}
#[test]
fn enabling_hardware_mode_closes_a_prior_software_lease() {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(128)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let w = s.recover("software-fixture", 1, true).unwrap();
    let _h = HardwareSupervisor::new(
        s,
        Box::new(RejectAllVerifier),
        "enrolled-key",
        "approved-boot",
        "fixed-policy-v1",
        1000,
    )
    .unwrap();
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
    assert_eq!(w.propose(read()), Err("authority_expired"));
}
#[test]
fn verifier_failure_revokes_lease_and_never_renews_it() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    h.challenge([2; 32], "first", 1).unwrap();
    assert_eq!(h.renew(proof(3)), Err("nonce_mismatch"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn valid_mock_renewal_cannot_revive_a_dead_lease() {
    let mut h = fixture(Box::new(verifier()));
    h.challenge([1; 32], "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    h.advance_fixture_clock(10000).unwrap();
    h.challenge([2; 32], "first", 1).unwrap();
    assert_eq!(h.renew(proof(2)), Err("authority_expired"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn challenge_budget_cannot_be_reset_by_worker_or_provider() {
    let mut h = fixture(Box::new(RejectAllVerifier));
    for i in 1..=128u8 {
        h.challenge([i; 32], "first", 1).unwrap();
        assert!(h.recover(proof(i)).is_err());
    }
    assert_eq!(
        h.challenge([129; 32], "first", 1).err(),
        Some("challenge_capacity_reached")
    );
}
#[test]
fn malformed_configuration_and_challenge_are_refused() {
    let mut h = fixture(Box::new(verifier()));
    assert!(h.challenge([0; 32], "first", 1).is_err());
    assert!(h.challenge([1; 32], "first\npolicy=bad", 1).is_err());
    assert!(h.challenge([1; 32], "first", 0).is_err());
}
