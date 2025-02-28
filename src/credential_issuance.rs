// Use items from curve25519-dalek, rand, and sha2.
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest};

// For convenience, we reuse helper functions from system_setup.
// (If these are not public in system_setup.rs, you could duplicate them here.)
use crate::system_setup::{random_scalar, scalar_from_hash, hash_to_point};

/// Represents the two Pedersen commitments in the blind token request.
pub struct BlindRequest {
    pub cm: RistrettoPoint,
    pub cm_k: RistrettoPoint,
}

/// Represents the user’s internal registration state:
/// – st_Rg = (a, r) for the attribute commitment,
/// – along with the derived value k and randomness r_k for committing to k.
pub struct RandA {
    pub a: Scalar,
    pub r: Scalar,
    pub k: Scalar,
    pub r_k: Scalar,
}

/// Represents a partial (unblinded) signature from one credential issuer.
pub struct PartialSignature {
    pub sig: RistrettoPoint,
}

/// Represents the final aggregated token (signature).
pub struct Token {
    pub sigma: RistrettoPoint,
}

/// A dummy zero-knowledge proof structure.
pub struct ZKProof {
    pub proof: Vec<u8>,
}

/// Represents a credential issuer’s information needed for token issuance.
pub struct IssuerInfo {
    pub sk: Scalar,
    pub pk: RistrettoPoint,
    pub agg_scalar: Scalar, // In practice, computed as H_agg({pk_1,...,pk_n}, pk)
}

/// -------------------------------
/// TokenRequest (User-side)
/// -------------------------------
/// The user has a unique attribute `a` and a VRF output `y_s` (from identity issuance).
/// The user:
/// 1. Generates a Pedersen commitment on `a`: cm = g^a h^r,
/// 2. Computes k = H''(enc(y_s)) (simulated by hashing y_s),
/// 3. Commits to k as cm_k = g^k h^r_k,
/// 4. Stores (a, r) along with k and r_k.
pub fn token_request(a: Scalar, y_s: RistrettoPoint) -> (BlindRequest, RandA) {
    let r = random_scalar();
    let g = RISTRETTO_BASEPOINT_POINT;
    // Use a secondary generator for Pedersen commitments (here derived from a fixed string).
    let h = hash_to_point(b"pedersen_h");
    let cm = a * g + r * h;
    
    // Compute k = H''(enc(y_s)). For simulation, hash y_s's compressed bytes.
    let k = scalar_from_hash(y_s.compress().as_bytes());
    let r_k = random_scalar();
    let cm_k = k * g + r_k * h;
    
    (BlindRequest { cm, cm_k }, RandA { a, r, k, r_k })
}

/// -------------------------------
/// TokenIssuance (Interactive Protocol)
/// -------------------------------
/// For each credential issuer:
///   1. The issuer “blindly signs” cm (simulated here as: ~s = sk * cm),
///   2. The user unblinds the signature: σ_j = ~s - r * pk (using additive notation),
///   3. The user aggregates partial signatures using aggregation scalars.
pub fn token_issuance(
    blind_req: &BlindRequest,
    issuer_infos: &[IssuerInfo],
    rand_a: &RandA,
) -> (Token, Vec<PartialSignature>) {
    let g = RISTRETTO_BASEPOINT_POINT;
    let mut partial_sigs = Vec::new();
    
    // For each issuer, simulate blind signing and unblinding.
    for issuer in issuer_infos.iter() {
        // Simulate blind signature: ~s = sk * cm.
        let blind_sig = issuer.sk * blind_req.cm;
        // Unblind: in additive notation, subtract r * pk.
        let sigma_j = blind_sig - rand_a.r * issuer.pk;
        partial_sigs.push(PartialSignature { sig: sigma_j });
    }
    
    // Aggregate partial signatures: sigma = Σ (agg_scalar_j * σ_j).
    let sigma = issuer_infos
        .iter()
        .zip(partial_sigs.iter())
        .fold(RistrettoPoint::default(), |acc, (issuer, ps)| {
            acc + issuer.agg_scalar * ps.sig
        });
    
    (Token { sigma }, partial_sigs)
}

/// -------------------------------
/// TokenProve (User-side ZK Proof)
/// -------------------------------
/// The user produces a zero-knowledge proof that they know the values behind:
/// - cm = Ped.Commit(a; r)
/// - cm_k = Ped.Commit(k; r_k)
/// - token is correctly aggregated, and k = H''(enc(y_s))
/// For simulation, we simply hash the token and internal state.
pub fn token_prove(token: &Token, _partial_sigs: &[PartialSignature], rand_a: &RandA) -> ZKProof {
    let mut hasher = Sha512::new();
    sha2::digest::Update::update(&mut hasher, token.sigma.compress().as_bytes());
    sha2::digest::Update::update(&mut hasher, rand_a.a.as_bytes());
    sha2::digest::Update::update(&mut hasher, rand_a.r.as_bytes());
    sha2::digest::Update::update(&mut hasher, rand_a.k.as_bytes());
    sha2::digest::Update::update(&mut hasher, rand_a.r_k.as_bytes());
    let proof_bytes = hasher.finalize();
    ZKProof {
        proof: proof_bytes.to_vec(),
    }
}

/// -------------------------------
/// TokenVerify (Credential Issuer-side)
/// -------------------------------
/// The issuers verify:
///   a. That the aggregated token is valid (simulated here),
///   b. That the user’s commitments and the ZK proof are well formed.
/// For simulation, we return true (verification succeeds).
pub fn token_verify(
    token: &Token,
    zk_proof: &ZKProof,
    _blind_req: &BlindRequest,
    _issuer_infos: &[IssuerInfo],
) -> bool {
    // In a full implementation, pairing-based checks and ZK verification would occur.
    true
}

/// -------------------------------
/// MicroCred (Interactive Protocol)
/// -------------------------------
/// The user obtains a micro-credential on one of their attributes.
/// For simulation, we simply print a message.
pub fn microcred(a_i: Scalar) {
    println!("Issuing micro-credential for attribute: {:?}", a_i);
    // In a full implementation, the user would compute:
    //   - A Pedersen commitment: cm_i = g^{r_i} + u_0^{k} + u_i^{a_i},
    //   - A zero-knowledge proof for the correctness of the commitment,
    // and interact with credential issuers.
}

/// -------------------------------
/// run_credential_issuance (Demonstration)
/// -------------------------------
/// This function demonstrates the overall protocol:
///   - The user performs TokenRequest,
///   - Interacts with dummy credential issuers for TokenIssuance,
///   - Generates a ZK proof via TokenProve,
///   - And verifies the token via TokenVerify,
///   - Finally, demonstrates a micro-credential issuance.
pub fn run_credential_issuance() {
    println!("--- Credential Issuance Protocol Demonstration ---");
    
    // Simulate the user's unique attribute 'a'.
    let user_attribute = random_scalar();
    // For simulation, let y_s be a random group element (normally from Identity Issuance).
    let y_s = random_scalar() * RISTRETTO_BASEPOINT_POINT;
    
    // TokenRequest: user commits to attribute and to derived value k.
    let (blind_req, rand_a) = token_request(user_attribute, y_s);
    println!("TokenRequest completed.");
    
    // Simulate a set of credential issuers (e.g., 3 issuers).
    let mut issuer_infos = Vec::new();
    for _ in 0..3 {
        let sk = random_scalar();
        let pk = sk * RISTRETTO_BASEPOINT_POINT;
        // For simulation, compute agg_scalar as a hash of pk.
        let agg_scalar = scalar_from_hash(pk.compress().as_bytes());
        issuer_infos.push(IssuerInfo { sk, pk, agg_scalar });
    }
    
    // TokenIssuance: user obtains partial signatures and aggregates them.
    let (token, partial_sigs) = token_issuance(&blind_req, &issuer_infos, &rand_a);
    println!("TokenIssuance completed. Token sigma: {:?}", token.sigma.compress());
    
    // TokenProve: user generates a zero-knowledge proof of correct token formation.
    let zk_proof = token_prove(&token, &partial_sigs, &rand_a);
    println!("TokenProve generated a proof ({} bytes).", zk_proof.proof.len());
    
    // TokenVerify: credential issuers verify the token and proof.
    let valid = token_verify(&token, &zk_proof, &blind_req, &issuer_infos);
    println!("TokenVerify result: {}", valid);
    
    // Demonstrate MicroCred issuance.
    microcred(user_attribute);
}
