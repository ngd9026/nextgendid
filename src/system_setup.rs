use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;

/// Helper: Generates a random scalar.
pub fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Helper: Derives a scalar from the SHA-512 hash of the input.
pub fn scalar_from_hash(data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    sha2::digest::Update::update(&mut hasher, data);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Helper: Hashes a message to a Ristretto point.
pub fn hash_to_point(message: &[u8]) -> RistrettoPoint {
    let hash = Sha512::digest(message);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

/// -------------------------------------------------------------------------
/// VRF Module: Implements key generation and a simplified VRF proof.
/// -------------------------------------------------------------------------
pub mod vrf {
    use super::*;

    /// VRF keypair with a secret scalar and public key.
    pub struct VRFKeypair {
        pub sk: Scalar,
        pub pk: RistrettoPoint,
    }

    /// A simplified Schnorr-style VRF proof.
    pub struct VRFProof {
        pub c: Scalar,
        pub r: Scalar,
    }

    /// Generates a VRF keypair.
    pub fn keygen() -> VRFKeypair {
        let sk = random_scalar();
        let pk = sk * RISTRETTO_BASEPOINT_POINT;
        VRFKeypair { sk, pk }
    }

    /// Given a secret key and a message, computes the VRF output and proof.
    pub fn prove(sk: &Scalar, message: &[u8]) -> (RistrettoPoint, VRFProof) {
        let h = hash_to_point(message);
        let gamma = sk * h;

        let k = random_scalar();
        let a = k * h;
        let b = k * RISTRETTO_BASEPOINT_POINT;

        let mut hasher = Sha512::new();
        sha2::digest::Update::update(&mut hasher, h.compress().as_bytes());
        sha2::digest::Update::update(&mut hasher, gamma.compress().as_bytes());
        sha2::digest::Update::update(&mut hasher, a.compress().as_bytes());
        sha2::digest::Update::update(&mut hasher, b.compress().as_bytes());
        let hash_result = hasher.finalize();
        let c = scalar_from_hash(&hash_result);
        let r = k - c * sk;

        (gamma, VRFProof { c, r })
    }
}

/// -------------------------------------------------------------------------
/// Pedersen Module: Generates Pedersen commitment parameters.
/// -------------------------------------------------------------------------
pub mod pedersen {
    use super::*;

    /// Pedersen commitment parameters: a set of generators.
    pub struct PedersenParameters {
        pub generators: Vec<RistrettoPoint>,
    }

    /// Sets up Pedersen commitment parameters (for committing to L+1 values).
    pub fn setup(count: usize) -> PedersenParameters {
        let mut generators = Vec::new();
        for i in 0..count {
            let mut hasher = Sha512::new();
            sha2::digest::Update::update(&mut hasher, b"Pedersen generator");
            sha2::digest::Update::update(&mut hasher, &i.to_le_bytes());
            let hash = hasher.finalize();
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(&hash);
            let point = RistrettoPoint::from_uniform_bytes(&bytes);
            generators.push(point);
        }
        PedersenParameters { generators }
    }
}

/// -------------------------------------------------------------------------
/// Credential Module: Sets up credential issuers and computes aggregate keys.
/// -------------------------------------------------------------------------
pub mod credential {
    use super::*;
    use sha2::Sha512;

    /// Credential issuer parameters.
    pub struct CredentialIssuer {
        pub sk: Scalar,
        pub pk: RistrettoPoint,
        pub agg_scalar: Scalar, // Computed via aggregation hash.
    }

    /// Shared public parameters for credential issuers.
    pub struct CredentialPublicParams {
        pub aggregate_pk: RistrettoPoint,
        pub token_dedup: HashMap<String, bool>,
        pub token_usage: HashMap<String, u64>,
    }

    /// Aggregation hash function: binds an issuer’s public key with the list of all public keys.
    pub fn h_agg(pks: &[RistrettoPoint], pk_j: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha512::new();
        for pk in pks {
            sha2::digest::Update::update(&mut hasher, pk.compress().as_bytes());
        }
        sha2::digest::Update::update(&mut hasher, pk_j.compress().as_bytes());
        scalar_from_hash(&hasher.finalize())
    }

    /// Sets up a committee of credential issuers and computes the aggregate public key.
    pub fn setup(n: usize) -> (Vec<CredentialIssuer>, CredentialPublicParams) {
        let mut issuers = Vec::new();
        let mut pks = Vec::new();

        // Each issuer generates a secret and public key.
        for _ in 0..n {
            let sk = random_scalar();
            let pk = sk * RISTRETTO_BASEPOINT_POINT;
            issuers.push(CredentialIssuer {
                sk,
                pk,
                agg_scalar: Scalar::default(), // default() represents zero.
            });
            pks.push(pk);
        }

        // Compute aggregation scalars for each issuer.
        for issuer in issuers.iter_mut() {
            issuer.agg_scalar = h_agg(&pks, &issuer.pk);
        }

        // Compute the aggregate public key: sum_j (agg_scalar * pk_j).
        let aggregate_pk = issuers.iter().fold(RistrettoPoint::default(), |acc, issuer| {
            acc + issuer.agg_scalar * issuer.pk
        });

        let public_params = CredentialPublicParams {
            aggregate_pk,
            token_dedup: HashMap::new(),
            token_usage: HashMap::new(),
        };

        (issuers, public_params)
    }
}

/// -------------------------------------------------------------------------
/// Identity Module: Interactive protocol between user and trusted identity issuer.
/// -------------------------------------------------------------------------
pub mod identity {
    use super::*;
    use super::vrf;

    /// The identity issuer’s keys.
    pub struct IdentityIssuer {
        pub sk: Scalar,
        pub vk: RistrettoPoint,
    }

    /// Sets up the identity issuer for a given user.
    /// Simulates:
    /// 1. Generating a VRF keypair.
    /// 2. Tying a secret to the user's identity.
    /// 3. Computing the VRF output and proof.
    pub fn setup(user_id: &str) -> (IdentityIssuer, RistrettoPoint, vrf::VRFProof) {
        let keypair = vrf::keygen();
        let s = scalar_from_hash(user_id.as_bytes());
        let (y_s, proof) = vrf::prove(&keypair.sk, &s.to_bytes());
        (IdentityIssuer { sk: keypair.sk, vk: keypair.pk }, y_s, proof)
    }
}

/// -------------------------------------------------------------------------
/// System-wide Setup: Combines VRF and Pedersen parameters.
/// -------------------------------------------------------------------------
pub struct VRFParams {
    pub basepoint: RistrettoPoint,
    pub secondary: RistrettoPoint,
}

pub struct PublicParameters {
    pub vrf_params: VRFParams,
    pub pedersen_params: pedersen::PedersenParameters,
}

/// Sets up system-wide public parameters.
pub fn system_setup(_lambda: usize, l: usize) -> PublicParameters {
    let secondary_hash = Sha512::digest(b"VRF secondary generator");
    let mut secondary_bytes = [0u8; 64];
    secondary_bytes.copy_from_slice(&secondary_hash);
    let vrf_params = VRFParams {
        basepoint: RISTRETTO_BASEPOINT_POINT,
        secondary: RistrettoPoint::from_uniform_bytes(&secondary_bytes),
    };
    let pedersen_params = pedersen::setup(l + 1);
    PublicParameters {
        vrf_params,
        pedersen_params,
    }
}

/// -------------------------------------------------------------------------
/// Global State
/// -------------------------------------------------------------------------
lazy_static! {
    pub static ref TKN_CNT_SET: Mutex<Vec<RistrettoPoint>> = Mutex::new(vec![]);
    pub static ref T_APP: Mutex<Vec<Vec<u8>>> = Mutex::new(vec![]);
}

/// -------------------------------------------------------------------------
/// Run: Demonstrates system setup and the various module operations.
/// -------------------------------------------------------------------------
pub fn run() {
    let lambda = 128;
    let l = 3;
    let public_params = system_setup(lambda, l);

    println!("--- System Setup ---");
    println!("VRF basepoint: {:?}", public_params.vrf_params.basepoint.compress());
    println!("VRF secondary generator: {:?}", public_params.vrf_params.secondary.compress());
    println!("Pedersen Generators:");
    for (i, g) in public_params.pedersen_params.generators.iter().enumerate() {
        println!("  Generator {}: {:?}", i, g.compress());
    }

    // Identity Issuer Setup Demo
    let user_id = "user123";
    let (identity_issuer, y_s, proof) = identity::setup(user_id);
    println!("\n--- Identity Issuer Setup ---");
    println!("Issuer VRF secret key: {:?}", identity_issuer.sk);
    println!("Issuer VRF verification key: {:?}", identity_issuer.vk.compress());
    println!("VRF output (y_s): {:?}", y_s.compress());
    println!("VRF proof: c = {:?}, r = {:?}", proof.c, proof.r);

    // Credential Issuer Setup Demo
    let n = 5;
    let (issuers, cred_public_params) = credential::setup(n);
    println!("\n--- Credential Issuer Setup ---");
    for (i, issuer) in issuers.iter().enumerate() {
        println!(
            "Issuer {}: secret = {:?}, pk = {:?}, agg_scalar = {:?}",
            i + 1,
            issuer.sk,
            issuer.pk.compress(),
            issuer.agg_scalar
        );
    }
    println!("Aggregate Public Key: {:?}", cred_public_params.aggregate_pk.compress());
}
