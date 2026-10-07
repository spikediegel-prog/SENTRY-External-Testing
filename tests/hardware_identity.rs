#![cfg(feature = "test-fixtures")]
use sentry_external_testing::hardware_identity::*;
use sentry_external_testing::*;

struct FixtureVerifier {
    draws: u8,
    hardware: bool,
    platform: bool,
    binding: bool,
    key: &'static str,
    profile: &'static str,
}
impl PlatformVerifier for FixtureVerifier {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        self.draws += 1;
        Ok(if self.draws == 1 {
            [77; 32]
        } else {
            [self.draws - 1; 32]
        })
    }
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
        draws: 0,
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
        session: [77; 32],
        sequence: n as u64,
        nonce: [n; 32],
        identity_signature: vec![1],
        quote: vec![2],
    }
}
fn issue(
    h: &mut HardwareSupervisor,
    _: u8,
    instance: &str,
    generation: u64,
) -> Result<Challenge, &'static str> {
    h.advance_fixture_clock(100).unwrap();
    h.challenge(instance, generation)
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
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(128)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    assert_eq!(
        HardwareSupervisor::new(
            s,
            Box::new(RejectAllVerifier),
            "key",
            "profile",
            "policy",
            1000
        )
        .err(),
        Some("trusted_randomness_not_configured")
    );
}
#[test]
fn finite_trusted_verifier_fixture_can_restore_existing_scope() {
    let mut h = fixture(Box::new(verifier()));
    issue(&mut h, 1, "first", 1).unwrap();
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
    let c = issue(&mut h, 1, "first", 1).unwrap();
    assert!(String::from_utf8(c.message())
        .unwrap()
        .ends_with("instance=first\ngeneration=1\npolicy=fixed-policy-v1\n"));
    assert!(issue(&mut h, 2, "other", 2).is_err());
}
#[test]
fn expired_proof_is_not_recovery() {
    let mut h = fixture(Box::new(verifier()));
    issue(&mut h, 1, "first", 1).unwrap();
    h.advance_fixture_clock(1001).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("challenge_expired"));
}
#[test]
fn nonce_mismatch_consumes_exchange_and_cannot_be_retried() {
    let mut h = fixture(Box::new(verifier()));
    issue(&mut h, 1, "first", 1).unwrap();
    let mut wrong = proof(1);
    wrong.nonce = [2; 32];
    assert_eq!(h.recover(wrong).err(), Some("nonce_mismatch"));
    assert_eq!(h.recover(proof(1)).err(), Some("no_pending_challenge"));
    let next = issue(&mut h, 1, "first", 1).unwrap();
    assert_ne!(next.sequence, 1);
}
#[test]
fn completed_challenge_cannot_be_replayed() {
    let mut h = fixture(Box::new(verifier()));
    issue(&mut h, 1, "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    assert_eq!(h.renew(proof(1)), Err("no_pending_challenge"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn software_provider_cannot_pass_hardware_required_policy() {
    let mut v = verifier();
    v.hardware = false;
    let mut h = fixture(Box::new(v));
    issue(&mut h, 1, "first", 1).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
}
#[test]
fn identity_signature_alone_is_not_platform_attestation() {
    let mut v = verifier();
    v.platform = false;
    let mut h = fixture(Box::new(v));
    issue(&mut h, 1, "first", 1).unwrap();
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
        issue(&mut h, 1, "first", 1).unwrap();
        assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
    }
}
#[test]
fn unbound_proof_is_rejected() {
    let mut v = verifier();
    v.binding = false;
    let mut h = fixture(Box::new(v));
    issue(&mut h, 1, "first", 1).unwrap();
    assert_eq!(h.recover(proof(1)).err(), Some("hardware_policy_rejected"));
}
#[test]
fn missing_or_oversized_evidence_is_rejected() {
    for quote in [vec![], vec![0; 65537]] {
        let mut h = fixture(Box::new(verifier()));
        issue(&mut h, 1, "first", 1).unwrap();
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
        Box::new(verifier()),
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
    issue(&mut h, 1, "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    issue(&mut h, 2, "first", 1).unwrap();
    assert_eq!(h.renew(proof(3)), Err("exchange_mismatch"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn valid_mock_renewal_cannot_revive_a_dead_lease() {
    let mut h = fixture(Box::new(verifier()));
    issue(&mut h, 1, "first", 1).unwrap();
    let w = h.recover(proof(1)).unwrap();
    h.advance_fixture_clock(10000).unwrap();
    issue(&mut h, 2, "first", 1).unwrap();
    assert_eq!(h.renew(proof(2)), Err("authority_expired"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
#[test]
fn continuous_issuance_has_no_lifetime_budget() {
    let mut h = fixture(Box::new(ConstantEntropy));
    for i in 1..=1024 {
        let c = issue(&mut h, 1, "first", 1).unwrap();
        assert_eq!(c.sequence, i);
        assert!(h.recover(bound_proof(&c)).is_err());
    }
}
#[test]
fn malformed_configuration_and_challenge_are_refused() {
    let mut h = fixture(Box::new(verifier()));
    assert!(issue(&mut h, 1, "first\npolicy=bad", 1).is_err());
    assert!(issue(&mut h, 1, "first", 0).is_err());
}

// Deliberately broken/repeating entropy demonstrates sequence protection inside one session.
struct ConstantEntropy;
impl PlatformVerifier for ConstantEntropy {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        Ok([77; 32])
    }
    fn verify(
        &mut self,
        _: &Challenge,
        _: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        Err("fixture_rejection")
    }
}
fn bound_proof(c: &Challenge) -> HardwareProof {
    HardwareProof {
        session: c.session,
        sequence: c.sequence,
        nonce: c.nonce,
        identity_signature: vec![1],
        quote: vec![2],
    }
}
#[test]
fn repeated_nonce_still_produces_distinct_challenge_bytes() {
    let mut h = fixture(Box::new(ConstantEntropy));
    let a = issue(&mut h, 1, "first", 1).unwrap();
    assert!(h.recover(bound_proof(&a)).is_err());
    let b = issue(&mut h, 1, "first", 1).unwrap();
    assert_eq!(a.nonce, b.nonce);
    assert_ne!(a.message(), b.message());
    assert_eq!(h.recover(bound_proof(&a)).err(), Some("exchange_mismatch"));
}
#[test]
fn challenge_flood_is_rate_limited_and_can_resume() {
    let mut h = fixture(Box::new(verifier()));
    let a = h.challenge("first", 1).unwrap();
    h.recover(bound_proof(&a)).unwrap();
    assert_eq!(
        h.challenge("first", 1).err(),
        Some("challenge_rate_limited")
    );
    h.advance_fixture_clock(100).unwrap();
    assert!(h.challenge("first", 1).is_ok());
}
#[test]
fn abandoned_exchange_expires_without_permanent_outage() {
    let mut h = fixture(Box::new(verifier()));
    let old = h.challenge("first", 1).unwrap();
    h.advance_fixture_clock(1000).unwrap();
    let next = h.challenge("first", 1).unwrap();
    assert_ne!(old.sequence, next.sequence);
    assert_eq!(
        h.recover(bound_proof(&old)).err(),
        Some("exchange_mismatch")
    );
}
struct SessionVerifier(u8);
impl PlatformVerifier for SessionVerifier {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        Ok([self.0; 32])
    }
    fn verify(
        &mut self,
        c: &Challenge,
        p: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        // Finite message-binding simulation, not cryptographic verification.
        if p.identity_signature != c.message() || p.quote != c.message() {
            return Err("fixture_binding_failed");
        }
        verifier().verify(c, p)
    }
}
#[test]
fn fresh_restart_session_rejects_old_proof_even_with_relabelled_envelope() {
    let mut old = fixture(Box::new(SessionVerifier(44)));
    let a = old.challenge("first", 1).unwrap();
    let mut p = bound_proof(&a);
    p.identity_signature = a.message();
    p.quote = a.message();
    let mut next = fixture(Box::new(SessionVerifier(45)));
    let b = next.challenge("first", 1).unwrap();
    assert_eq!(next.recover(p.clone()).err(), Some("exchange_mismatch"));
    next.advance_fixture_clock(100).unwrap();
    let c = next.challenge("first", 1).unwrap();
    p.session = b.session;
    p.sequence = c.sequence;
    p.nonce = c.nonce;
    assert_eq!(next.recover(p).err(), Some("fixture_binding_failed"));
}
struct ZeroEntropy;
impl PlatformVerifier for ZeroEntropy {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        Ok([0; 32])
    }
    fn verify(
        &mut self,
        _: &Challenge,
        _: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        unreachable!()
    }
}
#[test]
fn zero_session_entropy_is_rejected() {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(128)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    assert_eq!(
        HardwareSupervisor::new(s, Box::new(ZeroEntropy), "key", "profile", "policy", 1000).err(),
        Some("invalid_session_randomness")
    );
}
struct SlowVerifier;
impl PlatformVerifier for SlowVerifier {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        Ok([77; 32])
    }
    fn verify(
        &mut self,
        c: &Challenge,
        p: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        std::thread::sleep(std::time::Duration::from_millis(20));
        verifier().verify(c, p)
    }
}
#[test]
fn delayed_success_cannot_renew_after_deadline() {
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(128)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let mut h = HardwareSupervisor::new(
        s,
        Box::new(SlowVerifier),
        "enrolled-key",
        "approved-boot",
        "policy",
        10,
    )
    .unwrap();
    let c = h.challenge("first", 1).unwrap();
    assert!(matches!(
        h.recover(bound_proof(&c)).err(),
        Some("verification_deadline_expired" | "challenge_expired")
    ));
}

struct BrokenEntropy {
    draws: u8,
    zero: bool,
}
impl PlatformVerifier for BrokenEntropy {
    fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
        self.draws += 1;
        if self.draws < 3 {
            return Ok([77; 32]);
        }
        if self.zero {
            Ok([0; 32])
        } else {
            Err("fixture_entropy_failed")
        }
    }
    fn verify(
        &mut self,
        c: &Challenge,
        p: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        verifier().verify(c, p)
    }
}
#[test]
fn entropy_failure_revokes_an_existing_lease() {
    let mut h = fixture(Box::new(BrokenEntropy {
        draws: 0,
        zero: false,
    }));
    let c = h.challenge("first", 1).unwrap();
    let w = h.recover(bound_proof(&c)).unwrap();
    h.advance_fixture_clock(100).unwrap();
    assert_eq!(
        h.challenge("first", 1).err(),
        Some("fixture_entropy_failed")
    );
    assert_eq!(w.propose(read()), Err("authority_expired"));
}
#[test]
fn zero_nonce_revokes_an_existing_lease() {
    let mut h = fixture(Box::new(BrokenEntropy {
        draws: 0,
        zero: true,
    }));
    let c = h.challenge("first", 1).unwrap();
    let w = h.recover(bound_proof(&c)).unwrap();
    h.advance_fixture_clock(100).unwrap();
    assert_eq!(
        h.challenge("first", 1).err(),
        Some("invalid_nonce_randomness")
    );
    assert_eq!(w.propose(read()), Err("authority_expired"));
}
