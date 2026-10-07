//! Optional hardware-evidence policy plumbing. No built-in verifier accepts hardware claims.
//! Provider labels/signatures alone are not platform attestation.
use crate::{Supervisor, Worker};
use std::collections::BTreeSet;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 32],
    pub instance: String,
    pub generation: u64,
    pub policy_id: String,
}
impl Challenge {
    pub fn message(&self) -> Vec<u8> {
        let nonce: String = self.nonce.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "SENTRY-HARDWARE-IDENTITY-V1\nnonce={nonce}\ninstance={}\ngeneration={}\npolicy={}\n",
            self.instance, self.generation, self.policy_id
        )
        .into_bytes()
    }
}
#[derive(Clone, Debug)]
pub struct HardwareProof {
    pub nonce: [u8; 32],
    pub identity_signature: Vec<u8>,
    pub quote: Vec<u8>,
}
/// Only an independently trusted verifier may return these results. Never parse these booleans from worker input.
#[derive(Clone, Debug)]
pub struct VerifiedPlatform {
    pub enrolled_key_id: String,
    pub boot_profile: String,
    pub hardware_provenance_verified: bool,
    pub platform_state_verified: bool,
    pub binding_verified: bool,
}
pub trait PlatformVerifier: Send {
    /// Verify enrolled key signature, freshness/domain binding, quote signature, PCR/event-log policy,
    /// and hardware enrollment provenance. Failure/absence must return Err; no software downgrade.
    fn verify(
        &mut self,
        challenge: &Challenge,
        proof: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str>;
}
/// Default implementation: until a genuine independent verifier is installed, hardware authority stays closed.
pub struct RejectAllVerifier;
impl PlatformVerifier for RejectAllVerifier {
    fn verify(
        &mut self,
        _: &Challenge,
        _: &HardwareProof,
    ) -> Result<VerifiedPlatform, &'static str> {
        Err("hardware_verifier_not_configured")
    }
}
/// Owns the existing supervisor handle; workers receive only Worker ports.
/// This opt-in wrapper cannot add powers, expand policy, or automatically release access holds.
pub struct HardwareSupervisor {
    supervisor: Supervisor,
    verifier: Box<dyn PlatformVerifier>,
    key_id: String,
    profile: String,
    policy_id: String,
    pending: Option<(Challenge, u64)>,
    used: BTreeSet<[u8; 32]>,
    start: Instant,
    offset: u64,
    ttl_ms: u64,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
impl HardwareSupervisor {
    pub fn new(
        supervisor: Supervisor,
        verifier: Box<dyn PlatformVerifier>,
        key_id: &str,
        profile: &str,
        policy_id: &str,
        challenge_ttl_ms: u64,
    ) -> Result<Self, &'static str> {
        if !identifier(key_id)
            || !identifier(profile)
            || !identifier(policy_id)
            || !(1..=5000).contains(&challenge_ttl_ms)
        {
            return Err("invalid_hardware_policy");
        }
        // Enabling hardware-required mode revokes any previously issued software-fixture lease.
        supervisor.hardware_failure("hardware_mode_enabled");
        Ok(Self {
            supervisor,
            verifier,
            key_id: key_id.into(),
            profile: profile.into(),
            policy_id: policy_id.into(),
            pending: None,
            used: BTreeSet::new(),
            start: Instant::now(),
            offset: 0,
            ttl_ms: challenge_ttl_ms,
        })
    }
    fn now(&self) -> u64 {
        (self.start.elapsed().as_millis().min(u64::MAX as u128) as u64).saturating_add(self.offset)
    }
    /// Nonce must come from the independent verifier's CSPRNG, not the model or provider.
    /// This method does not renew authority. It reserves the nonce even if the exchange is abandoned.
    pub fn challenge(
        &mut self,
        nonce: [u8; 32],
        instance: &str,
        generation: u64,
    ) -> Result<Challenge, &'static str> {
        if self.pending.is_some() {
            return Err("challenge_pending");
        }
        if !identifier(instance) || generation == 0 || nonce == [0; 32] {
            return Err("invalid_challenge");
        }
        if self.used.contains(&nonce) {
            return Err("challenge_replay");
        }
        if self.used.len() >= 128 {
            return Err("challenge_capacity_reached");
        }
        let challenge = Challenge {
            nonce,
            instance: instance.into(),
            generation,
            policy_id: self.policy_id.clone(),
        };
        self.used.insert(nonce);
        self.pending = Some((challenge.clone(), self.now().saturating_add(self.ttl_ms)));
        Ok(challenge)
    }
    fn reject(&self, reason: &'static str) -> &'static str {
        // Existing trusted revocation path expires capabilities before recording evidence.
        self.supervisor.hardware_failure(reason);
        reason
    }
    fn validate(&mut self, proof: HardwareProof) -> Result<Challenge, &'static str> {
        let (challenge, expires) = match self.pending.take() {
            Some(v) => v,
            None => return Err(self.reject("no_pending_challenge")),
        };
        if self.now() >= expires {
            return Err(self.reject("challenge_expired"));
        }
        if proof.nonce != challenge.nonce {
            return Err(self.reject("nonce_mismatch"));
        }
        if proof.identity_signature.is_empty()
            || proof.identity_signature.len() > 8192
            || proof.quote.is_empty()
            || proof.quote.len() > 65536
        {
            return Err(self.reject("invalid_proof_size"));
        }
        let result = match self.verifier.verify(&challenge, &proof) {
            Ok(v) => v,
            Err(e) => return Err(self.reject(e)),
        };
        if result.enrolled_key_id != self.key_id
            || result.boot_profile != self.profile
            || !result.hardware_provenance_verified
            || !result.platform_state_verified
            || !result.binding_verified
        {
            return Err(self.reject("hardware_policy_rejected"));
        }
        if self.now() >= expires {
            return Err(self.reject("verification_deadline_expired"));
        }
        Ok(challenge)
    }
    pub fn recover(&mut self, proof: HardwareProof) -> Result<Worker, &'static str> {
        let challenge = self.validate(proof)?;
        match self
            .supervisor
            .recover(&challenge.instance, challenge.generation, true)
        {
            Ok(worker) => Ok(worker),
            Err(e) => Err(self.reject(e)),
        }
    }
    pub fn renew(&mut self, proof: HardwareProof) -> Result<(), &'static str> {
        let challenge = self.validate(proof)?;
        match self
            .supervisor
            .attest(&challenge.instance, challenge.generation, true)
        {
            Ok(()) => Ok(()),
            Err(e) => Err(self.reject(e)),
        }
    }
    #[cfg(feature = "test-fixtures")]
    pub fn advance_fixture_clock(&mut self, ms: u64) -> Result<(), &'static str> {
        self.offset = self.offset.checked_add(ms).ok_or("clock_overflow")?;
        self.supervisor.advance_fixture_clock(ms)
    }
}
