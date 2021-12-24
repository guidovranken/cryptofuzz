use k256::{SecretKey, PublicKey, ecdsa::signature::Signature, ecdsa::VerifyingKey, ecdsa::SigningKey, ecdsa::signature::Signer, ecdsa::signature::DigestVerifier, elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, EncodedPoint, Scalar};
use sha2::{Sha256, Digest};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use std::ops::Neg;

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


#[no_mangle]
pub extern "C" fn k256_ecc_point_add(a_bytes: &[u8; 65], b_bytes: &[u8; 65], res_bytes: &mut [u8; 65]) -> bool {
    let a = match EncodedPoint::from_bytes(a_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let a_affine = match AffinePoint::from_encoded_point(&a) {
        Some(_v) => _v,
        None => return false,
    };

    let a_projective: ProjectivePoint = a_affine.into();

    let b = match EncodedPoint::from_bytes(b_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let b_affine = match AffinePoint::from_encoded_point(&b) {
        Some(_v) => _v,
        None => return false,
    };

    let b_projective: ProjectivePoint = b_affine.into();

    let res_projective = a_projective + b_projective;
    let res_affine = res_projective.to_affine();

    let res = res_affine.to_encoded_point(false);
    if res.len() != 65 {
        return false
    }
    res_bytes.copy_from_slice(&res.as_bytes());

    return true

}

#[no_mangle]
pub extern "C" fn k256_ecc_point_mul(a_bytes: &[u8; 65], b_bytes: &[u8; 32], res_bytes: &mut [u8; 65]) -> bool {
    let a = match EncodedPoint::from_bytes(a_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let a_affine = match AffinePoint::from_encoded_point(&a) {
        Some(_v) => _v,
        None => return false,
    };

    let a_projective: ProjectivePoint = a_affine.into();

    let b = Scalar::from_bytes_reduced(b_bytes.into());

    let res_projective = a_projective * b;
    let res_affine = res_projective.to_affine();

    let res = res_affine.to_encoded_point(false);
    if res.len() != 65 {
        return false
    }
    res_bytes.copy_from_slice(&res.as_bytes());
    return true;
}

#[no_mangle]
pub extern "C" fn k256_ecc_point_neg(a_bytes: &[u8; 65], res_bytes: &mut [u8; 65]) -> bool {
    let a = match EncodedPoint::from_bytes(a_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let a_affine = match AffinePoint::from_encoded_point(&a) {
        Some(_v) => _v,
        None => return false,
    };

    let a_projective: ProjectivePoint = a_affine.into();

    let res_projective = a_projective.neg();
    let res_affine = res_projective.to_affine();

    let res = res_affine.to_encoded_point(false);
    if res.len() != 65 {
        return false
    }
    res_bytes.copy_from_slice(&res.as_bytes());
    return true;
}

#[no_mangle]
pub extern "C" fn k256_ecc_point_dbl(a_bytes: &[u8; 65], res_bytes: &mut [u8; 65]) -> bool {
    let a = match EncodedPoint::from_bytes(a_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let a_affine = match AffinePoint::from_encoded_point(&a) {
        Some(_v) => _v,
        None => return false,
    };

    let a_projective: ProjectivePoint = a_affine.into();

    let res_projective = a_projective + a_projective;
    let res_affine = res_projective.to_affine();

    let res = res_affine.to_encoded_point(false);
    res_bytes.copy_from_slice(&res.as_bytes());

    return true

}
