//! Opt-in cryptographic evidence verification. Trust anchors/enrollment are installed by an
//! independent administrator, never inferred from submitted evidence. No TPM provisioning.
use crate::hardware_identity::{Challenge, HardwareProof, PlatformVerifier, VerifiedPlatform};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_REQUEST: usize = 256 * 1024;
pub const MAX_RESPONSE: usize = 4096;
const MAX_MANIFEST: usize = 16384;
const MAX_LOG: usize = 16384;
type Result<T> = std::result::Result<T, &'static str>;

pub fn os_random_bytes() -> Result<[u8; 32]> {
    let mut out = [0; 32];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| "os_randomness_failed")?;
    if out == [0; 32] {
        return Err("os_randomness_invalid");
    }
    Ok(out)
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA256 size")
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str, limit: usize) -> Result<Vec<u8>> {
    if s.len() > limit * 2 || s.len() % 2 != 0 {
        return Err("invalid_hex_size");
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(v: u8) -> Result<u8> {
                match v {
                    b'0'..=b'9' => Ok(v - b'0'),
                    b'a'..=b'f' => Ok(v - b'a' + 10),
                    _ => Err("invalid_hex"),
                }
            }
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Signed exact JSON bytes, domain-separated from all signatures over device evidence.
pub fn enrollment_message(manifest: &[u8]) -> Vec<u8> {
    let mut out = b"SENTRY-ENROLLMENT-V1\n".to_vec();
    out.extend_from_slice(manifest);
    out
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub version: u32,
    pub record_id: String,
    pub key_id: String,
    pub boot_profile: String,
    pub policy_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub hardware_class: String,
    pub binding_method: String,
    pub enrollment_audit_id: String,
    /// SHA256 fingerprint of independently accepted endorsement identity; not proof on its own.
    pub endorsement_identity_sha256: String,
    /// PKCS#1 DER public key; fingerprint included to detect mismatched enrollment material.
    pub identity_public_der: String,
    pub identity_public_sha256: String,
    /// TPMT_PUBLIC, excluding TPM2B size prefix. Restricted RSA-2048, SHA256, RSASSA.
    pub ak_public: String,
    pub ak_name: String,
    pub ak_qualified_name: String,
    pub pcr_indices: Vec<u8>,
    pub pcr_sha256: Vec<String>,
    /// Exact approved binary TCG EFI event log, independently reviewed at enrollment.
    pub event_log_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteBundle {
    pub version: u32,
    /// Raw TPMS_ATTEST as written by tpm2_quote -m, not TPM2B_ATTEST.
    pub attestation: String,
    /// Marshalled TPMT_SIGNATURE as written by tpm2_quote -s (default TSS format).
    pub signature: String,
    pub event_log: String,
}
/// Collection/encoding only. Reads bounded snapshots, never makes hardware trust claims.
pub fn package_quote_files(attest: &Path, signature: &Path, event_log: &Path) -> Result<Vec<u8>> {
    fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| "quote_file_open_failed")?
            .take((max + 1) as u64)
            .read_to_end(&mut out)
            .map_err(|_| "quote_file_read_failed")?;
        if out.is_empty() || out.len() > max {
            return Err("quote_file_size_rejected");
        }
        Ok(out)
    }
    let b = QuoteBundle {
        version: 1,
        attestation: hex(&read(attest, 2048)?),
        signature: hex(&read(signature, 512)?),
        event_log: hex(&read(event_log, MAX_LOG)?),
    };
    let bytes = serde_json::to_vec(&b).map_err(|_| "quote_bundle_encoding_failed")?;
    if bytes.len() > 65536 {
        return Err("quote_bundle_size_rejected");
    }
    Ok(bytes)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("truncated_tpm_structure")?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or("truncated_tpm_structure")?;
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn le16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn le32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn done(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err("trailing_tpm_structure")
        }
    }
}
fn verify_rsa(key: &[u8], message: &[u8], sig: &[u8]) -> Result<()> {
    if key.len() > 4096 || sig.len() != 256 {
        return Err("unsupported_rsa_key_or_signature");
    }
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key)
        .verify(message, sig)
        .map_err(|_| "rsa_signature_rejected")
}
fn ak_modulus(public: &[u8]) -> Result<&[u8]> {
    let mut c = Cursor::new(public);
    if c.u16()? != 0x0001 || c.u16()? != 0x000b {
        return Err("unsupported_ak_type");
    }
    let attrs = c.u32()?;
    // fixedTPM, fixedParent, sensitiveDataOrigin, restricted and sign; no decrypt.
    if attrs & 0x0005_0032 != 0x0005_0032 || attrs & 0x0002_0000 != 0 {
        return Err("unapproved_ak_attributes");
    }
    if c.sized()?.len() > 32
        || c.u16()? != 0x0010
        || c.u16()? != 0x0014
        || c.u16()? != 0x000b
        || c.u16()? != 2048
    {
        return Err("unsupported_ak_scheme");
    }
    let exponent = c.u32()?;
    if exponent != 0 && exponent != 65537 {
        return Err("unsupported_ak_exponent");
    }
    let modulus = c.sized()?;
    c.done()?;
    if modulus.len() != 256 || modulus[0] & 0x80 == 0 {
        return Err("unsupported_ak_modulus");
    }
    Ok(modulus)
}
/// Conservative replay of bounded TCG EFI Spec ID Event03 + Event2 SHA256 measurements.
/// StartupLocality and unsupported algorithms/structures fail closed; no general IMA parser.
fn replay_event_log(log: &[u8]) -> Result<[[u8; 32]; 24]> {
    let mut c = Cursor::new(log);
    if c.le32()? != 0 || c.le32()? != 3 || c.take(20)? != [0; 20] {
        return Err("unsupported_event_log_header");
    }
    let len = c.le32()? as usize;
    let spec = c.take(len)?;
    let mut s = Cursor::new(spec);
    if s.take(16)? != b"Spec ID Event03\0" {
        return Err("unsupported_event_log_spec");
    }
    s.take(4)?; // platform class
    let minor = s.u8()?;
    let major = s.u8()?;
    s.u8()?;
    let uintn = s.u8()?;
    if major != 2 || minor != 0 || !matches!(uintn, 1 | 2) {
        return Err("unsupported_event_log_version");
    }
    let count = s.le32()?;
    if count == 0 || count > 8 {
        return Err("unsupported_event_log_algorithms");
    }
    let mut algorithms = Vec::new();
    for _ in 0..count {
        let alg = s.le16()?;
        let size = s.le16()? as usize;
        if algorithms.iter().any(|(a, _)| *a == alg)
            || !matches!((alg, size), (4, 20) | (11, 32) | (12, 48) | (13, 64))
        {
            return Err("unsupported_event_log_algorithms");
        }
        algorithms.push((alg, size));
    }
    if !algorithms.contains(&(11, 32)) {
        return Err("missing_sha256_bank");
    }
    let vendor = s.u8()? as usize;
    s.take(vendor)?;
    s.done()?;
    let mut pcrs = [[0; 32]; 24];
    let mut events = 0;
    while c.at < log.len() {
        events += 1;
        if events > 512 {
            return Err("event_log_capacity");
        }
        let pcr = c.le32()? as usize;
        let kind = c.le32()?;
        let count = c.le32()? as usize;
        if pcr >= 24 || count == 0 || count > algorithms.len() {
            return Err("invalid_event_log_entry");
        }
        let mut seen = Vec::new();
        let mut measurement = None;
        for _ in 0..count {
            let alg = c.le16()?;
            if seen.contains(&alg) {
                return Err("duplicate_event_digest");
            }
            seen.push(alg);
            let size = algorithms
                .iter()
                .find(|(a, _)| *a == alg)
                .ok_or("unknown_event_digest")?
                .1;
            let bytes = c.take(size)?;
            if alg == 11 {
                measurement = Some(bytes);
            }
        }
        let len = c.le32()? as usize;
        let event = c.take(len)?;
        if kind == 3 {
            // Locality changes PCR0 initial state; do not silently replay as zero.
            if event.starts_with(b"StartupLocality") {
                return Err("unsupported_startup_locality");
            }
        } else {
            let bytes = measurement.ok_or("missing_event_sha256")?;
            let mut extend = pcrs[pcr].to_vec();
            extend.extend_from_slice(bytes);
            pcrs[pcr] = sha256(&extend);
        }
    }
    Ok(pcrs)
}

pub struct CryptographicVerifier {
    enrollment: Enrollment,
    identity: Vec<u8>,
    ak: Vec<u8>,
    qualified_name: Vec<u8>,
}
impl CryptographicVerifier {
    pub fn from_enrollment(
        root_public_der: &[u8],
        manifest: &[u8],
        signature: &[u8],
        pinned_manifest_sha256: [u8; 32],
    ) -> Result<Self> {
        if manifest.is_empty()
            || manifest.len() > MAX_MANIFEST
            || sha256(manifest) != pinned_manifest_sha256
        {
            return Err("enrollment_pin_mismatch");
        }
        verify_rsa(root_public_der, &enrollment_message(manifest), signature)?;
        let e: Enrollment =
            serde_json::from_slice(manifest).map_err(|_| "invalid_enrollment_schema")?;
        if e.version != 1
            || [
                &e.record_id,
                &e.key_id,
                &e.boot_profile,
                &e.policy_id,
                &e.enrollment_audit_id,
            ]
            .iter()
            .any(|s| !identifier(s))
        {
            return Err("invalid_enrollment_identifiers");
        }
        if e.hardware_class != "physical-tpm2"
            || e.binding_method != "credential-activation-and-key-certification"
        {
            return Err("unapproved_enrollment_provenance");
        }
        if unhex(&e.endorsement_identity_sha256, 32)?.len() != 32
            || e.not_after <= e.not_before
            || e.not_after - e.not_before > 86400
        {
            return Err("invalid_enrollment_validity");
        }
        if e.pcr_indices.is_empty()
            || e.pcr_indices.len() != e.pcr_sha256.len()
            || e.pcr_indices.len() > 24
            || e.pcr_indices.iter().any(|p| *p >= 24)
            || e.pcr_indices.windows(2).any(|p| p[0] >= p[1])
        {
            return Err("invalid_pcr_profile");
        }
        for p in &e.pcr_sha256 {
            if unhex(p, 32)?.len() != 32 {
                return Err("invalid_pcr_value");
            }
        }
        if unhex(&e.event_log_sha256, 32)?.len() != 32 {
            return Err("invalid_event_log_pin");
        }
        let identity = unhex(&e.identity_public_der, 4096)?;
        if hex(&sha256(&identity)) != e.identity_public_sha256 {
            return Err("identity_fingerprint_mismatch");
        }
        let ak = unhex(&e.ak_public, 1024)?;
        ak_modulus(&ak)?;
        let mut name = vec![0, 11];
        name.extend_from_slice(&sha256(&ak));
        if unhex(&e.ak_name, 34)? != name {
            return Err("ak_name_mismatch");
        }
        let qualified_name = unhex(&e.ak_qualified_name, 34)?;
        if qualified_name.len() != 34 || qualified_name[..2] != [0, 11] {
            return Err("invalid_ak_qualified_name");
        }
        let out = Self {
            enrollment: e,
            identity,
            ak,
            qualified_name,
        };
        out.check_validity()?;
        Ok(out)
    }
    fn check_validity(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "trusted_clock_failed")?
            .as_secs();
        if now < self.enrollment.not_before || now >= self.enrollment.not_after {
            return Err("enrollment_expired_or_not_yet_valid");
        }
        Ok(())
    }
}
impl PlatformVerifier for CryptographicVerifier {
    fn random_bytes(&mut self) -> Result<[u8; 32]> {
        os_random_bytes()
    }
    fn verify(&mut self, ch: &Challenge, proof: &HardwareProof) -> Result<VerifiedPlatform> {
        self.check_validity()?;
        if !identifier(&ch.instance)
            || ch.generation == 0
            || ch.sequence == 0
            || ch.session == [0; 32]
            || ch.nonce == [0; 32]
            || ch.policy_id != self.enrollment.policy_id
            || proof.session != ch.session
            || proof.sequence != ch.sequence
            || proof.nonce != ch.nonce
        {
            return Err("challenge_binding_rejected");
        }
        if proof.identity_signature.len() != 256
            || proof.quote.is_empty()
            || proof.quote.len() > 65536
        {
            return Err("invalid_proof_size");
        }
        verify_rsa(&self.identity, &ch.message(), &proof.identity_signature)?;
        let b: QuoteBundle =
            serde_json::from_slice(&proof.quote).map_err(|_| "invalid_quote_bundle")?;
        if b.version != 1 {
            return Err("unsupported_quote_bundle");
        }
        let attest = unhex(&b.attestation, 2048)?;
        let sig = unhex(&b.signature, 512)?;
        let log = unhex(&b.event_log, MAX_LOG)?;
        let mut sc = Cursor::new(&sig);
        if sc.u16()? != 0x0014 || sc.u16()? != 0x000b {
            return Err("unsupported_quote_signature");
        }
        let signature = sc.sized()?;
        sc.done()?;
        if signature.len() != 256 {
            return Err("invalid_quote_signature_size");
        }
        signature::RsaPublicKeyComponents {
            n: ak_modulus(&self.ak)?,
            e: &[1, 0, 1],
        }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, &attest, signature)
        .map_err(|_| "quote_signature_rejected")?;
        let mut c = Cursor::new(&attest);
        if c.u32()? != 0xff54_4347 || c.u16()? != 0x8018 {
            return Err("not_a_tpm_quote");
        }
        if c.sized()? != self.qualified_name || c.sized()? != sha256(&ch.message()) {
            return Err("quote_binding_rejected");
        }
        c.take(16)?; // clock, resetCount, restartCount; freshness relies on challenge, not these fields.
        if c.u8()? != 1 {
            return Err("unsafe_tpm_clock");
        }
        c.take(8)?; // firmwareVersion is retained in signed quote, not a runtime trust claim.
        if c.u32()? != 1 || c.u16()? != 0x000b || c.u8()? != 3 {
            return Err("unsupported_pcr_selection");
        }
        let selected = c.take(3)?;
        let mut expected = [0u8; 3];
        for p in &self.enrollment.pcr_indices {
            expected[(*p / 8) as usize] |= 1 << (*p % 8);
        }
        if selected != expected {
            return Err("pcr_selection_rejected");
        }
        let pcr_digest = c.sized()?;
        c.done()?;
        if hex(&sha256(&log)) != self.enrollment.event_log_sha256 {
            return Err("event_log_pin_rejected");
        }
        let replay = replay_event_log(&log)?;
        let mut values = Vec::new();
        for (p, approved) in self
            .enrollment
            .pcr_indices
            .iter()
            .zip(&self.enrollment.pcr_sha256)
        {
            if hex(&replay[*p as usize]) != *approved {
                return Err("event_log_pcr_rejected");
            }
            values.extend_from_slice(&replay[*p as usize]);
        }
        if pcr_digest != sha256(&values) {
            return Err("quote_pcr_digest_rejected");
        }
        self.check_validity()?;
        // Provenance is delegated to the independently pinned enrollment authority's signed
        // activation/certification record. We do not perform that hardware ceremony here.
        Ok(VerifiedPlatform {
            enrolled_key_id: self.enrollment.key_id.clone(),
            boot_profile: self.enrollment.boot_profile.clone(),
            hardware_provenance_verified: true,
            platform_state_verified: true,
            binding_verified: true,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequest {
    pub version: u32,
    pub root_public_der: Vec<u8>,
    pub manifest: Vec<u8>,
    pub enrollment_signature: Vec<u8>,
    pub pinned_manifest_sha256: [u8; 32],
    pub challenge: Challenge,
    pub proof: HardwareProof,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierResponse {
    pub version: u32,
    pub accepted: Option<VerifiedPlatform>,
    pub error: Option<String>,
}
/// The root pin/config comes only from a trusted bootstrap caller, not submitted evidence.
pub fn handle_request(bytes: &[u8]) -> VerifierResponse {
    let result = (|| {
        if bytes.len() > MAX_REQUEST {
            return Err("verifier_request_too_large");
        }
        let r: VerifierRequest =
            serde_json::from_slice(bytes).map_err(|_| "invalid_verifier_request")?;
        if r.version != 1 {
            return Err("unsupported_verifier_protocol");
        }
        CryptographicVerifier::from_enrollment(
            &r.root_public_der,
            &r.manifest,
            &r.enrollment_signature,
            r.pinned_manifest_sha256,
        )?
        .verify(&r.challenge, &r.proof)
    })();
    match result {
        Ok(v) => VerifierResponse {
            version: 1,
            accepted: Some(v),
            error: None,
        },
        Err(e) => VerifierResponse {
            version: 1,
            accepted: None,
            error: Some(e.into()),
        },
    }
}

/// One short-lived trusted child per exchange. Process separation is not an OS sandbox.
pub struct ProcessVerifier {
    executable: PathBuf,
    root: Vec<u8>,
    manifest: Vec<u8>,
    enrollment_signature: Vec<u8>,
    pin: [u8; 32],
    timeout: Duration,
    #[cfg(feature = "test-fixtures")]
    fixture_behavior: Option<String>,
}
impl ProcessVerifier {
    pub fn new(
        executable: &Path,
        root: Vec<u8>,
        manifest: Vec<u8>,
        enrollment_signature: Vec<u8>,
        pin: [u8; 32],
        timeout: Duration,
    ) -> Result<Self> {
        if !executable.is_absolute()
            || !executable.is_file()
            || root.len() > 4096
            || manifest.len() > MAX_MANIFEST
            || enrollment_signature.len() != 256
            || sha256(&manifest) != pin
            || !(Duration::from_millis(50)..=Duration::from_millis(2000)).contains(&timeout)
        {
            return Err("invalid_verifier_configuration");
        }
        Ok(Self {
            executable: executable
                .canonicalize()
                .map_err(|_| "invalid_verifier_path")?,
            root,
            manifest,
            enrollment_signature,
            pin,
            timeout,
            #[cfg(feature = "test-fixtures")]
            fixture_behavior: None,
        })
    }
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_behavior(&mut self, behavior: &str) -> Result<()> {
        if !matches!(behavior, "stall" | "oversize" | "crash" | "malformed") {
            return Err("unknown_verifier_fixture");
        }
        self.fixture_behavior = Some(behavior.into());
        Ok(())
    }
    fn exchange(&self, bytes: Vec<u8>) -> Result<VerifiedPlatform> {
        if bytes.len() > MAX_REQUEST {
            return Err("verifier_request_too_large");
        }
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", system_root);
            }
        }
        #[cfg(feature = "test-fixtures")]
        if let Some(mode) = &self.fixture_behavior {
            command.arg("--fixture").arg(mode);
        }
        let start = Instant::now();
        let mut child = command.spawn().map_err(|_| "verifier_spawn_failed")?;
        let mut input = child.stdin.take().ok_or("verifier_pipe_failed")?;
        let output = child.stdout.take().ok_or("verifier_pipe_failed")?;
        let (tx, rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = input.write_all(&bytes);
            drop(input);
            result
        });
        let reader = std::thread::spawn(move || {
            let mut data = Vec::new();
            let result = output
                .take((MAX_RESPONSE + 1) as u64)
                .read_to_end(&mut data);
            let _ = tx.send(if result.is_err() {
                Err("verifier_output_failed")
            } else if data.len() > MAX_RESPONSE {
                Err("verifier_output_too_large")
            } else {
                Ok(data)
            });
        });
        let mut response = None;
        let result = loop {
            if start.elapsed() >= self.timeout {
                break Err("verifier_timeout");
            }
            if response.is_none() {
                match rx.try_recv() {
                    Ok(Ok(v)) => response = Some(v),
                    Ok(Err(e)) => break Err(e),
                    Err(mpsc::TryRecvError::Disconnected) => break Err("verifier_output_failed"),
                    Err(mpsc::TryRecvError::Empty) => (),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) if !status.success() => break Err("verifier_process_failed"),
                Ok(Some(_)) if response.is_some() => {
                    let data = response.take().unwrap();
                    let r: VerifierResponse = match serde_json::from_slice(&data) {
                        Ok(v) => v,
                        Err(_) => break Err("invalid_verifier_response"),
                    };
                    if r.version != 1 {
                        break Err("invalid_verifier_response");
                    }
                    if start.elapsed() >= self.timeout {
                        break Err("verifier_timeout");
                    }
                    break match (r.accepted, r.error) {
                        (Some(v), None) => Ok(v),
                        (None, Some(_)) => Err("cryptographic_verifier_rejected"),
                        _ => Err("invalid_verifier_response"),
                    };
                }
                Err(_) => break Err("verifier_wait_failed"),
                _ => (),
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        // Our verifier does not spawn descendants. Host-level tampering is outside this boundary.
        let _ = child.kill();
        let _ = child.wait();
        let _ = writer.join();
        let _ = reader.join();
        result
    }
}
impl PlatformVerifier for ProcessVerifier {
    fn random_bytes(&mut self) -> Result<[u8; 32]> {
        os_random_bytes()
    }
    fn verify(&mut self, challenge: &Challenge, proof: &HardwareProof) -> Result<VerifiedPlatform> {
        if proof.identity_signature.len() > 8192 || proof.quote.len() > 65536 {
            return Err("invalid_proof_size");
        }
        let r = VerifierRequest {
            version: 1,
            root_public_der: self.root.clone(),
            manifest: self.manifest.clone(),
            enrollment_signature: self.enrollment_signature.clone(),
            pinned_manifest_sha256: self.pin,
            challenge: challenge.clone(),
            proof: proof.clone(),
        };
        let bytes = serde_json::to_vec(&r).map_err(|_| "verifier_request_encoding_failed")?;
        self.exchange(bytes)
    }
}
