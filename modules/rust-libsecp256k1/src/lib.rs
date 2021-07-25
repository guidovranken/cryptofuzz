use libsecp256k1::{SecretKey, PublicKey, Signature, Message, RecoveryId, SharedSecret, verify, sign, recover, ECMULT_CONTEXT};
use libsecp256k1::curve::{Affine, Jacobian, Scalar};
use arrayref::{array_mut_ref};
use sha2;

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecc_privatetopublic(sk_bytes: &[u8; 32], pk_bytes: &mut [u8; 65]) -> bool {
    let sk = match SecretKey::parse(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = PublicKey::from_secret_key(&sk);
    pk_bytes.copy_from_slice(&pk.serialize());
    return true;
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecdsa_verify(msg_bytes: &[u8; 32], sig_bytes: &[u8; 64], pk_bytes: &[u8; 65]) -> bool {
    let msg = Message::parse(msg_bytes);
    let sig = match Signature::parse_standard(sig_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = match PublicKey::parse(pk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    return verify(&msg, &sig, &pk);
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecdsa_sign(msg_bytes: &[u8; 32], sk_bytes: &[u8; 32], sig_bytes: &mut [u8; 64]) -> bool {
    let msg = Message::parse(msg_bytes);
    let sk = match SecretKey::parse(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let sig = sign(&msg, &sk).0;
    sig_bytes.copy_from_slice(&sig.serialize());
    return true;
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_validate_pubkey(pk_bytes: &[u8; 65]) -> bool {
    match PublicKey::parse(pk_bytes) {
        Ok(_v) => true,
        Err(_e) => false,
    }
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecdsa_recover(msg_bytes: &[u8; 32], sig_bytes: &mut [u8; 64], id: u8, pk_bytes: &mut [u8; 65]) -> bool {
    let msg = Message::parse(msg_bytes);
    let sig = match Signature::parse_standard(sig_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let recovery_id = match RecoveryId::parse(id) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = match recover(&msg, &sig, &recovery_id) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    pk_bytes.copy_from_slice(&pk.serialize());
    return true;
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecdh_derive(sk_bytes: &[u8; 32], pk_bytes: &[u8; 65], shared_bytes: &mut [u8; 32]) -> bool {
    let sk = match SecretKey::parse(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = match PublicKey::parse(pk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let res = match SharedSecret::<sha2::Sha256>::new(&pk, &sk) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let shared = res.as_ref();
    if shared.len() == 32 {
        shared_bytes.copy_from_slice(&shared);
    }
    return true;
}

#[no_mangle]
pub extern "C" fn parity_libsecp256k1_ecc_point_mul(scalar_bytes: &[u8; 32], point_bytes: &[u8; 65], res_bytes: &mut [u8; 64]) -> bool {
    let mut scalar = Scalar::default();
    if bool::from(scalar.set_b32(&scalar_bytes)) == true {
        return false
    }
    if scalar.is_zero() {
        return false
    }

    let pk = match PublicKey::parse(point_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };

    let pk_affine: Affine = pk.into();

    let mut res: Jacobian = Jacobian::default();
    ECMULT_CONTEXT.ecmult_const(&mut res, &pk_affine, &scalar);
    if res.is_infinity() {
        return false;
    }

    let mut res_affine: Affine = Affine::default();
    res_affine.set_gej(&res);

    res_affine.x.normalize_var();
    res_affine.y.normalize_var();

    res_affine.x.fill_b32(array_mut_ref!(res_bytes, 0, 32));
    res_affine.y.fill_b32(array_mut_ref!(res_bytes, 32, 32));

    return true
}

/*
pub extern "C" fn main() {
    let sk_bytes: [u8; 32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
    //let sk_bytes: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let msg_bytes: [u8; 32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut pk_bytes: [u8; 65]= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut sig_bytes: [u8; 64]= [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    println!("{:?}", ecc_privatetopublic(&sk_bytes, &mut pk_bytes));
    println!("{:?}", ecdsa_sign(&msg_bytes, &sk_bytes, &mut sig_bytes));
    println!("{:?}", ecdsa_verify(&msg_bytes, &sig_bytes, &pk_bytes));
    println!("{:?}", validate_pubkey(&pk_bytes));
    println!("{:?}", pk_bytes.to_vec());
    println!("{:?}", sig_bytes.to_vec());
}
*/
