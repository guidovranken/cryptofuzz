use k256::{SecretKey, PublicKey, ecdsa::signature::Signature, ecdsa::VerifyingKey, ecdsa::SigningKey, ecdsa::signature::Signer, ecdsa::signature::DigestVerifier, ecdsa::signature::Verifier, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Sha256, Digest};

#[no_mangle]
pub extern "C" fn k256_ecc_privatetopublic(sk_bytes: &[u8; 32], pk_bytes: &mut [u8; 65]) -> bool {
    let sk = match SecretKey::from_bytes(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(false);
    let pk_bin = pk_point.to_bytes();
    pk_bytes.copy_from_slice(&pk_bin);
    return true;
}

#[no_mangle]
pub extern "C" fn k256_validate_pubkey(pk_bytes: &[u8; 65]) -> bool {
    match PublicKey::from_sec1_bytes(pk_bytes) {
        Ok(_v) => true,
        Err(_e) => false,
    }
}

#[no_mangle]
pub extern "C" fn k256_ecdsa_sign(msg_bytes: &[u8; 32], sk_bytes: &[u8; 32], sig_bytes: &mut [u8; 64]) -> bool {
    let sk = match SigningKey::from_bytes(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let sig: k256::ecdsa::Signature = sk.sign(msg_bytes);
    sig_bytes.copy_from_slice(&sig.as_bytes());
    return true;
}

#[no_mangle]
pub extern "C" fn k256_ecdsa_verify(msg_bytes: &[u8; 32], sig_bytes: &[u8; 64], pk_bytes: &[u8; 65]) -> bool {
    let mut sig = match k256::ecdsa::Signature::from_bytes(sig_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    sig.normalize_s().unwrap();
    let pk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    return pk.verify_digest(Sha256::new().chain(msg_bytes), &sig).is_ok();
}
