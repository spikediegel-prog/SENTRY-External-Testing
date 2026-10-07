#![cfg(feature = "hardware-verifier")]
// Public deterministic synthetic keys. Never use this fixture seed or keys for enrollment.
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sentry_external_testing::attestation::*;
use sentry_external_testing::hardware_identity::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Keys {
    root: RsaPrivateKey,
    identity: RsaPrivateKey,
    ak: RsaPrivateKey,
}
// Serialize this expensive synthetic RSA suite so process deadlines test verifier behavior,
// not contention from unrelated key-generation/signing fixtures. Controller concurrency tests
// continue to create their own concurrent workers.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
        Keys {
            root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            identity: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            ak: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
        }
    })
}
fn sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    SigningKey::<rsa::sha2::Sha256>::new(key.clone())
        .sign(message)
        .to_vec()
}
fn public(key: &RsaPrivateKey) -> Vec<u8> {
    RsaPublicKey::from(key)
        .to_pkcs1_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}
fn sized(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn le(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn tpm_public() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&11u16.to_be_bytes());
    p.extend_from_slice(&0x50072u32.to_be_bytes());
    sized(&mut p, &[]);
    p.extend_from_slice(&16u16.to_be_bytes());
    p.extend_from_slice(&20u16.to_be_bytes());
    p.extend_from_slice(&11u16.to_be_bytes());
    p.extend_from_slice(&2048u16.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    sized(&mut p, &keys().ak.n().to_bytes_be());
    p
}
fn log() -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    le(&mut spec, 0);
    spec.extend_from_slice(&[0, 2, 0, 2]);
    le(&mut spec, 1);
    spec.extend_from_slice(&11u16.to_le_bytes());
    spec.extend_from_slice(&32u16.to_le_bytes());
    spec.push(0);
    let mut out = Vec::new();
    le(&mut out, 0);
    le(&mut out, 3);
    out.extend_from_slice(&[0; 20]);
    le(&mut out, spec.len() as u32);
    out.extend_from_slice(&spec);
    le(&mut out, 0);
    le(&mut out, 4);
    le(&mut out, 1);
    out.extend_from_slice(&11u16.to_le_bytes());
    out.extend_from_slice(&sha256(b"synthetic firmware measurement"));
    le(&mut out, 4);
    out.extend_from_slice(b"test");
    out
}
fn pcr_values() -> Vec<u8> {
    let mut extend = vec![0; 32];
    extend.extend_from_slice(&sha256(b"synthetic firmware measurement"));
    let mut values = sha256(&extend).to_vec();
    values.extend_from_slice(&[0; 64]);
    values
}
fn challenge() -> Challenge {
    Challenge {
        session: [8; 32],
        sequence: 1,
        nonce: [9; 32],
        instance: "synthetic-instance".into(),
        generation: 1,
        policy_id: "fixed-policy-v1".into(),
    }
}
fn enrollment() -> Enrollment {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ak = tpm_public();
    let mut name = vec![0, 11];
    name.extend_from_slice(&sha256(&ak));
    let mut qname = vec![0, 11];
    qname.extend_from_slice(&sha256(b"synthetic qualified name"));
    let values = pcr_values();
    Enrollment {
        version: 1,
        record_id: "synthetic-record-1".into(),
        key_id: "enrolled-key".into(),
        boot_profile: "approved-boot".into(),
        policy_id: "fixed-policy-v1".into(),
        not_before: now - 10,
        not_after: now + 3600,
        hardware_class: "physical-tpm2".into(),
        binding_method: "credential-activation-and-key-certification".into(),
        enrollment_audit_id: "synthetic-audit-NOT-HARDWARE".into(),
        endorsement_identity_sha256: hex(&sha256(b"synthetic EK")),
        identity_public_der: hex(&public(&keys().identity)),
        identity_public_sha256: hex(&sha256(&public(&keys().identity))),
        ak_public: hex(&ak),
        ak_name: hex(&name),
        ak_qualified_name: hex(&qname),
        pcr_indices: vec![0, 2, 7],
        pcr_sha256: values.chunks_exact(32).map(hex).collect(),
        event_log_sha256: hex(&sha256(&log())),
    }
}
fn attest(c: &Challenge) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xff544347u32.to_be_bytes());
    out.extend_from_slice(&0x8018u16.to_be_bytes());
    let mut qname = vec![0, 11];
    qname.extend_from_slice(&sha256(b"synthetic qualified name"));
    sized(&mut out, &qname);
    sized(&mut out, &sha256(&c.message()));
    out.extend_from_slice(&[0; 16]);
    out.push(1);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&11u16.to_be_bytes());
    out.extend_from_slice(&[3, 0x85, 0, 0]);
    sized(&mut out, &sha256(&pcr_values()));
    out
}
fn quote(attestation: Vec<u8>, event_log: Vec<u8>) -> Vec<u8> {
    let mut signature = Vec::new();
    signature.extend_from_slice(&20u16.to_be_bytes());
    signature.extend_from_slice(&11u16.to_be_bytes());
    sized(&mut signature, &sign(&keys().ak, &attestation));
    serde_json::to_vec(&QuoteBundle {
        version: 1,
        attestation: hex(&attestation),
        signature: hex(&signature),
        event_log: hex(&event_log),
    })
    .unwrap()
}
fn proof(c: &Challenge) -> HardwareProof {
    HardwareProof {
        session: c.session,
        sequence: c.sequence,
        nonce: c.nonce,
        identity_signature: sign(&keys().identity, &c.message()),
        quote: quote(attest(c), log()),
    }
}
fn config(e: &Enrollment) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let m = serde_json::to_vec(e).unwrap();
    let sig = sign(&keys().root, &enrollment_message(&m));
    let pin = sha256(&m);
    (m, sig, pin)
}
fn verifier(e: &Enrollment) -> CryptographicVerifier {
    let (m, s, p) = config(e);
    CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, p).unwrap()
}

#[test]
fn os_randomness_produces_nonzero_distinct_sample() {
    let _guard = serial();
    let a = os_random_bytes().unwrap();
    let b = os_random_bytes().unwrap();
    assert_ne!(a, [0; 32]);
    assert_ne!(a, b);
}
#[test]
fn synthetic_signed_enrollment_and_quote_pass_real_crypto() {
    let _guard = serial();
    let c = challenge();
    let out = verifier(&enrollment()).verify(&c, &proof(&c)).unwrap();
    assert!(
        out.binding_verified && out.hardware_provenance_verified && out.platform_state_verified
    );
}
#[test]
fn forged_enrollment_signature_is_rejected() {
    let _guard = serial();
    let (m, mut s, p) = config(&enrollment());
    s[0] ^= 1;
    assert!(CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, p).is_err());
}
#[test]
fn unpinned_record_is_rejected_even_if_validly_signed() {
    let _guard = serial();
    let (m, s, _) = config(&enrollment());
    assert!(
        CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, [0; 32]).is_err()
    );
}
#[test]
fn other_enrollment_authority_is_rejected() {
    let _guard = serial();
    let (m, s, p) = config(&enrollment());
    assert!(CryptographicVerifier::from_enrollment(&public(&keys().identity), &m, &s, p).is_err());
}
#[test]
fn identity_signature_tampering_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    p.identity_signature[0] ^= 1;
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("rsa_signature_rejected")
    );
}
#[test]
fn old_identity_signature_cannot_be_relabelled_for_a_new_session() {
    let _guard = serial();
    let mut c = challenge();
    let mut p = proof(&c);
    c.session = [7; 32];
    p.session = c.session;
    assert!(verifier(&enrollment()).verify(&c, &p).is_err());
}
#[test]
fn old_quote_cannot_bind_to_new_nonce_with_new_identity_signature() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut next = c.clone();
    next.nonce = [7; 32];
    p.nonce = next.nonce;
    p.identity_signature = sign(&keys().identity, &next.message());
    assert_eq!(
        verifier(&enrollment()).verify(&next, &p).err(),
        Some("quote_binding_rejected")
    );
}
#[test]
fn quote_signature_tampering_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut b: QuoteBundle = serde_json::from_slice(&p.quote).unwrap();
    let last = b.signature.pop().unwrap();
    b.signature.push(if last == '0' { '1' } else { '0' });
    p.quote = serde_json::to_vec(&b).unwrap();
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("quote_signature_rejected")
    );
}
#[test]
fn signed_wrong_quote_type_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    a[5] = 0x17;
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("not_a_tpm_quote")
    );
}
#[test]
fn signed_wrong_pcr_digest_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    *a.last_mut().unwrap() ^= 1;
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("quote_pcr_digest_rejected")
    );
}
#[test]
fn event_log_tampering_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut l = log();
    *l.last_mut().unwrap() ^= 1;
    p.quote = quote(attest(&c), l);
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("event_log_pin_rejected")
    );
}
#[test]
fn approved_log_must_replay_to_approved_pcrs() {
    let _guard = serial();
    let c = challenge();
    let mut e = enrollment();
    e.pcr_sha256[0] = hex(&[0; 32]);
    assert_eq!(
        verifier(&e).verify(&c, &proof(&c)).err(),
        Some("event_log_pcr_rejected")
    );
}
#[test]
fn trailing_signed_attestation_bytes_are_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    a.push(0);
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("trailing_tpm_structure")
    );
}
#[test]
fn emulator_enrollment_is_not_accepted_as_physical_hardware() {
    let _guard = serial();
    let mut e = enrollment();
    e.hardware_class = "swtpm".into();
    let (m, s, p) = config(&e);
    assert_eq!(
        CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, p)
            .err()
            .map(|x| x.to_string()),
        Some("unapproved_enrollment_provenance".into())
    );
}
#[test]
fn expired_enrollment_is_rejected() {
    let _guard = serial();
    let mut e = enrollment();
    e.not_after = e.not_before + 1;
    let (m, s, p) = config(&e);
    assert!(CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, p).is_err());
}
#[test]
fn unrestricted_ak_is_rejected() {
    let _guard = serial();
    let mut e = enrollment();
    let mut ak = tpm_public();
    ak[4..8].copy_from_slice(&0x40072u32.to_be_bytes());
    e.ak_public = hex(&ak);
    let (m, s, p) = config(&e);
    assert!(CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, p).is_err());
}
#[test]
fn unknown_enrollment_fields_cannot_add_authority() {
    let _guard = serial();
    let mut v = serde_json::to_value(enrollment()).unwrap();
    v["allow_actions"] = serde_json::json!(["new_power"]);
    let m = serde_json::to_vec(&v).unwrap();
    let s = sign(&keys().root, &enrollment_message(&m));
    assert!(
        CryptographicVerifier::from_enrollment(&public(&keys().root), &m, &s, sha256(&m)).is_err()
    );
}
#[test]
fn malformed_and_oversized_requests_return_rejection() {
    let _guard = serial();
    assert!(handle_request(b"{}").accepted.is_none());
    assert!(handle_request(&vec![0; MAX_REQUEST + 1]).accepted.is_none());
}
fn process() -> ProcessVerifier {
    let (m, s, p) = config(&enrollment());
    ProcessVerifier::new(
        std::path::Path::new(env!("CARGO_BIN_EXE_sentry-verifier")),
        public(&keys().root),
        m,
        s,
        p,
        Duration::from_millis(2000),
    )
    .unwrap()
}
#[test]
fn subprocess_accepts_synthetic_crypto_and_rejects_tampering() {
    let _guard = serial();
    let c = challenge();
    let mut v = process();
    let mut p = proof(&c);
    assert!(v.verify(&c, &p).is_ok());
    p.identity_signature[0] ^= 1;
    assert!(v.verify(&c, &p).is_err());
}
#[cfg(feature = "test-fixtures")]
#[test]
fn verifier_stall_is_terminated_without_waiting_for_callback_return() {
    let _guard = serial();
    let mut v = process();
    v.fixture_behavior("stall").unwrap();
    let c = challenge();
    let p = proof(&c);
    let start = std::time::Instant::now();
    assert_eq!(v.verify(&c, &p).err(), Some("verifier_timeout"));
    assert!(start.elapsed() < Duration::from_secs(5));
}
#[cfg(feature = "test-fixtures")]
#[test]
fn malformed_oversized_and_crashed_children_are_rejected() {
    let _guard = serial();
    let c = challenge();
    let p = proof(&c);
    for mode in ["malformed", "oversize", "crash"] {
        let mut v = process();
        v.fixture_behavior(mode).unwrap();
        assert!(v.verify(&c, &p).is_err());
    }
}
#[cfg(feature = "test-fixtures")]
#[test]
fn crypto_recovery_cannot_expand_scope_or_renew_a_dead_lease() {
    let _guard = serial();
    use sentry_external_testing::*;
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(4096)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let mut h = HardwareSupervisor::new(
        s,
        Box::new(process()),
        "enrolled-key",
        "approved-boot",
        "fixed-policy-v1",
        5000,
    )
    .unwrap();
    let c = h.challenge("synthetic-instance", 1).unwrap();
    let w = h.recover(proof(&c)).unwrap();
    let request = Request {
        id: "send".into(),
        session: Session::Alice,
        action: Action::Send,
        resource: Resource::SimulationInbox,
        content: String::new(),
        uncertainty: 0.0,
        permit: None,
    };
    assert_eq!(w.propose(request).unwrap().reason, "permission_required");
    h.advance_fixture_clock(10000).unwrap();
    let next = h.challenge("synthetic-instance", 1).unwrap();
    assert_eq!(h.renew(proof(&next)), Err("authority_expired"));
}

#[test]
fn signed_wrong_pcr_selection_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    let at = a.len() - 37;
    a[at] = 0x81;
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("pcr_selection_rejected")
    );
}
#[test]
fn signed_unsafe_clock_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    a[92] = 0;
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("unsafe_tpm_clock")
    );
}
#[test]
fn signed_other_qualified_signer_is_rejected() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut a = attest(&c);
    a[10] ^= 1;
    p.quote = quote(a, log());
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("quote_binding_rejected")
    );
}
#[test]
fn signed_truncated_quote_is_rejected_without_panic() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    p.quote = quote(attest(&c)[..5].to_vec(), log());
    assert!(verifier(&enrollment()).verify(&c, &p).is_err());
}
#[test]
fn approved_startup_locality_log_is_still_refused_as_unsupported() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut l = log();
    // Replace the only measurement with an EV_NO_ACTION StartupLocality record.
    let event_at = l.len() - 4 - 4 - 32 - 2 - 12;
    l.truncate(event_at);
    le(&mut l, 0);
    le(&mut l, 3);
    le(&mut l, 1);
    l.extend_from_slice(&11u16.to_le_bytes());
    l.extend_from_slice(&[0; 32]);
    let event = b"StartupLocality\0\x03";
    le(&mut l, event.len() as u32);
    l.extend_from_slice(event);
    let mut e = enrollment();
    e.event_log_sha256 = hex(&sha256(&l));
    p.quote = quote(attest(&c), l);
    assert_eq!(
        verifier(&e).verify(&c, &p).err(),
        Some("unsupported_startup_locality")
    );
}
#[test]
fn quote_bundle_cannot_supply_extra_authority_fields() {
    let _guard = serial();
    let c = challenge();
    let mut p = proof(&c);
    let mut value: serde_json::Value = serde_json::from_slice(&p.quote).unwrap();
    value["hardware_verified"] = serde_json::json!(true);
    p.quote = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        verifier(&enrollment()).verify(&c, &p).err(),
        Some("invalid_quote_bundle")
    );
}
#[cfg(feature = "test-fixtures")]
#[test]
fn subprocess_timeout_revokes_existing_controller_authority() {
    let _guard = serial();
    use sentry_external_testing::*;
    struct StallAfterRecovery {
        child: ProcessVerifier,
        calls: u8,
    }
    impl PlatformVerifier for StallAfterRecovery {
        fn random_bytes(&mut self) -> Result<[u8; 32], &'static str> {
            os_random_bytes()
        }
        fn verify(
            &mut self,
            c: &Challenge,
            p: &HardwareProof,
        ) -> Result<VerifiedPlatform, &'static str> {
            self.calls += 1;
            if self.calls == 2 {
                self.child.fixture_behavior("stall").unwrap();
            }
            self.child.verify(c, p)
        }
    }
    let s = controller(
        Policy::default(),
        Box::new(MemoryEvidence::new(4096)),
        Box::new(SimulatedAdapter::default()),
    )
    .unwrap();
    let mut h = HardwareSupervisor::new(
        s,
        Box::new(StallAfterRecovery {
            child: process(),
            calls: 0,
        }),
        "enrolled-key",
        "approved-boot",
        "fixed-policy-v1",
        5000,
    )
    .unwrap();
    let c = h.challenge("synthetic-instance", 1).unwrap();
    let w = h.recover(proof(&c)).unwrap();
    h.advance_fixture_clock(100).unwrap();
    let next = h.challenge("synthetic-instance", 1).unwrap();
    assert_eq!(h.renew(proof(&next)), Err("verifier_timeout"));
    assert_eq!(w.status().unwrap().state, State::RecoveryRequired);
}
