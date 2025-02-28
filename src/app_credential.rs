use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use lazy_static::lazy_static;
use std::sync::Mutex;
// Import helper functions and global state from system_setup.
use crate::system_setup::{random_scalar, hash_to_point, scalar_from_hash, TKN_CNT_SET};

/// --- Dummy Cryptographic Primitives ---
pub fn vrf_eval(sk: &Scalar, cnt: u64) -> (RistrettoPoint, Vec<u8>) {
    let cnt_scalar = Scalar::from(cnt);
    let token = sk * (RISTRETTO_BASEPOINT_POINT * cnt_scalar);
    let mut hasher = Sha512::new();
    hasher.update(sk.as_bytes());
    hasher.update(&cnt.to_le_bytes());
    let proof = hasher.finalize().to_vec();
    (token, proof)
}

pub fn vrf_verify(_vk: &RistrettoPoint, _token: &RistrettoPoint, _cnt: u64, _proof: &[u8]) -> bool {
    true
}

pub fn sign(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn validate(signature: &[u8]) -> bool {
    !signature.is_empty()
}

pub fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(key);
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn kem_keygen() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let mut pk = vec![0u8; 32];
    let mut sk = vec![0u8; 32];
    rng.fill_bytes(&mut pk);
    rng.fill_bytes(&mut sk);
    (pk, sk)
}

pub fn kem_encrypt(_pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let mut shared = vec![0u8; 32];
    let mut c = vec![0u8; 32];
    rng.fill_bytes(&mut shared);
    rng.fill_bytes(&mut c);
    (shared, c)
}

pub fn kem_decrypt(_sk: &[u8], _c: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let mut shared = vec![0u8; 32];
    rng.fill_bytes(&mut shared);
    shared
}

pub fn kdf(key: &[u8], salt: &[u8], ell: usize) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(key);
    hasher.update(salt);
    let result = hasher.finalize();
    result[..ell.min(result.len())].to_vec()
}

pub fn prf(key: &[u8], l: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(key);
    hasher.update(l);
    hasher.finalize().to_vec()
}

pub fn zkpok(_data: &[u8]) -> Vec<u8> {
    vec![1, 2, 3]
}

pub fn zkverify(_data: &[u8], _proof: &[u8]) -> bool {
    true
}

/// --- User Registration Functions ---

/// Structure for a Registration Request.
pub struct RegReq {
    pub vk_vrf: RistrettoPoint,
    pub tkn_cnt: RistrettoPoint,
    pub pi_vrf: Vec<u8>,
    pub sigma: Vec<u8>,
}

/// Generates a registration request using VRF.
pub fn user_register_request(cnt_init: u64) -> RegReq {
    let sk_vrf = random_scalar();
    let vk_vrf = sk_vrf * RISTRETTO_BASEPOINT_POINT;
    let (tkn_cnt, pi_vrf) = vrf_eval(&sk_vrf, cnt_init);
    let sigma = sign(tkn_cnt.compress().as_bytes());
    RegReq { vk_vrf, tkn_cnt, pi_vrf, sigma }
}

/// Verifies a registration request; if valid, adds the token to global state.
pub fn vrfy_register_request(reg_req: &RegReq, cnt_init: u64) -> Option<RistrettoPoint> {
    {
        let tkn_set = TKN_CNT_SET.lock().unwrap();
        if tkn_set.iter().any(|t| t == &reg_req.tkn_cnt) {
            return None;
        }
    }
    if !vrf_verify(&reg_req.vk_vrf, &reg_req.tkn_cnt, cnt_init, &reg_req.pi_vrf) {
        return None;
    }
    if !validate(&reg_req.sigma) {
        return None;
    }
    {
        let mut tkn_set = TKN_CNT_SET.lock().unwrap();
        tkn_set.push(reg_req.tkn_cnt);
    }
    Some(reg_req.tkn_cnt)
}

/// --- NextGen.AuthSetup ---
pub fn nextgen_auth_setup() -> Vec<u8> {
    let (pk_v, sk_v) = kem_keygen();
    let (k_shared_user, c) = kem_encrypt(&pk_v);
    let _k_shared_verifier = kem_decrypt(&sk_v, &c);
    let k_shared = k_shared_user;
    let mut rng = OsRng;
    let mut pk_user = vec![0u8; 32];
    rng.fill_bytes(&mut pk_user);
    let session_id = b"session123";
    let mut hasher = Sha512::new();
    hasher.update(&pk_v);
    hasher.update(&pk_user);
    hasher.update(session_id);
    let salt = hasher.finalize().to_vec();
    kdf(&k_shared, &salt, 32)
}

/// --- AppCredential Functions ---

/// Structure for the authentication request.
pub struct AuthRequest {
    pub tkn_cnt: RistrettoPoint,
    pub cnt: u64,
    pub pi_vrf: Vec<u8>,
    pub vk_vrf: RistrettoPoint,
    pub mac: Vec<u8>,
    pub inclusion_req: (Vec<u8>, Vec<u8>, RistrettoPoint), // (sigma, ZKP, tkn_cnt)
}

/// Structure for the credential.
pub struct Credential {
    pub tau: RistrettoPoint,
    pub pi: Vec<u8>,
}

/// Final AppCredential structure.
pub struct AppCredential {
    pub cred: Credential,
    pub tg: Vec<u8>,
    pub auth_req: AuthRequest,
}

/// Obtains an application credential.
pub fn app_credential(
    a_i: Vec<Scalar>,          // All user attributes.
    s_i: Vec<Vec<u8>>,         // Associated signatures (dummy).
    _prv_u: (Scalar, Scalar),  // User private info (unused here).
    l: u64,                    // Application message.
    phi: &[u8],                // Application-specific statement.
    A_l: Vec<Scalar>,          // Subset of attributes for the application.
    cnt: u64,                  // Current counter.
    k_e: &[u8],                // Session key from AuthSetup.
    ctx: &[u8],                // Context string.
) -> AppCredential {
    let sk_vrf = random_scalar();
    let vk_vrf = sk_vrf * RISTRETTO_BASEPOINT_POINT;
    let new_cnt = cnt + 1;
    let (tkn_cnt, pi_vrf) = vrf_eval(&sk_vrf, new_cnt);
    let mut mac_input = tkn_cnt.compress().as_bytes().to_vec();
    mac_input.extend_from_slice(ctx);
    let mac = hmac(k_e, &mac_input);
    let mut zkp_hasher = Sha512::new();
    zkp_hasher.update(tkn_cnt.compress().as_bytes());
    let zkp = zkp_hasher.finalize().to_vec();
    let mut sign_input = zkp.clone();
    sign_input.extend_from_slice(tkn_cnt.compress().as_bytes());
    let sigma = sign(&sign_input);
    let inclusion_req = (sigma, zkp, tkn_cnt);

    let r = random_scalar();
    let g = RISTRETTO_BASEPOINT_POINT;
    let u0 = hash_to_point(b"u0");
    let mut tau = r * g;
    let q = A_l.len() as u64;
    let k_dummy = random_scalar();
    tau = tau + (u0 * (Scalar::from(q) * k_dummy));
    for (i, a_val) in A_l.iter().enumerate() {
        let u_i = hash_to_point(format!("u{}", i).as_bytes());
        tau = tau + u_i * a_val;
    }
    let mut zeta = vk_vrf * r;
    for s in s_i.iter() {
        let s_scalar = scalar_from_hash(s);
        zeta = zeta + (vk_vrf * s_scalar);
    }
    let l_bytes = l.to_le_bytes();
    let tg = prf(k_e, &l_bytes);
    let mut pi_hasher = Sha512::new();
    pi_hasher.update(tau.compress().as_bytes());
    pi_hasher.update(&tg);
    pi_hasher.update(phi);
    let pi = pi_hasher.finalize().to_vec();
    let cred = Credential { tau, pi };
    let auth_req = AuthRequest {
        tkn_cnt,
        cnt: new_cnt,
        pi_vrf,
        vk_vrf,
        mac,
        inclusion_req,
    };
    AppCredential { cred, tg, auth_req }
}

/// Verifies the application credential.
pub fn verify_cred(
    cred: &Credential,
    l: u64,
    phi: &[u8],
    tg: &[u8],
    t_app: &mut Vec<Vec<u8>>,
    auth_req: &AuthRequest,
) -> bool {
    if cred.pi.is_empty() {
        return false;
    }
    if !vrf_verify(&auth_req.vk_vrf, &auth_req.tkn_cnt, auth_req.cnt, &auth_req.pi_vrf) {
        return false;
    }
    if !validate(&auth_req.inclusion_req.0) {
        return false;
    }
    if t_app.contains(&tg.to_vec()) {
        return false;
    }
    t_app.push(tg.to_vec());
    true
}

/// Verifies the inclusionRequest from the user.
pub fn nextgen_vrfy_auth_request(inclusion_req: &(Vec<u8>, Vec<u8>, RistrettoPoint)) -> Option<RistrettoPoint> {
    {
        let tkn_set = TKN_CNT_SET.lock().unwrap();
        if tkn_set.iter().any(|t| t == &inclusion_req.2) {
            return None;
        }
    }
    if !validate(&inclusion_req.0) || !zkverify(inclusion_req.1.as_slice(), inclusion_req.1.as_slice()) {
        return None;
    }
    {
        let mut tkn_set = TKN_CNT_SET.lock().unwrap();
        tkn_set.push(inclusion_req.2);
    }
    Some(inclusion_req.2)
}

/// Demo function to run the entire AppCredential protocol steps.
pub fn run_app_credential() {
    println!("--- AppCredential Demo ---");
    
    // UserRegisterRequest demo.
    let reg_req = user_register_request(1);
    println!("Registration Request generated.");
    if let Some(p_tkn) = vrfy_register_request(&reg_req, 1) {
        println!("Registration Request verified. Public token: {:?}", p_tkn.compress());
    } else {
        println!("Registration Request verification failed.");
    }

    // NextGen.AuthSetup demo.
    let k_e = nextgen_auth_setup();
    println!("Derived session key (k_e): {:?}", k_e);

    // AppCredential demo.
    let a_i = vec![random_scalar(), random_scalar()];
    let s_i = vec![vec![1, 2, 3], vec![4, 5, 6]]; // dummy signatures
    let prv_u = (random_scalar(), random_scalar());
    let l_val = 42u64;
    let phi = b"dummy phi";
    let A_l = a_i.clone();
    let cnt = 1;
    let ctx = b"context";
    let app_cred = app_credential(a_i, s_i, prv_u, l_val, phi, A_l, cnt, &k_e, ctx);
    println!("AppCredential generated. tg: {:?}", app_cred.tg);

    // VerifyCred demo.
    let mut t_app = vec![];
    let verified = verify_cred(&app_cred.cred, l_val, phi, &app_cred.tg, &mut t_app, &app_cred.auth_req);
    println!("Credential verification result: {}", verified);

    // NextGen.VrfyAuthRequest demo.
    if let Some(tkn) = nextgen_vrfy_auth_request(&app_cred.auth_req.inclusion_req) {
        println!("VrfyAuthRequest succeeded. tkn: {:?}", tkn.compress());
    } else {
        println!("VrfyAuthRequest failed.");
    }
}
