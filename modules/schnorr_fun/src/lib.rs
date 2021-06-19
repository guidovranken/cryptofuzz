use schnorr_fun::{
    fun::{marker::*, Scalar, XOnly},
    Schnorr,
    Message,
    Signature,
    nonce::{AddTag,Deterministic}
};

use sha2::Sha256;

#[no_mangle]
pub extern "C" fn schnorr_fun_schnorr_sign(msg_bytes: *mut u8, msg_size: libc::size_t, priv_bytes: &[u8; 32], sig_bytes: &mut [u8; 64], pk_bytes: &mut [u8; 32]) -> bool {
    let nonce_gen = Deterministic::<Sha256>::default();
    let p = match Scalar::from_bytes_mod_order(*priv_bytes).mark::<NonZero>() {
        Some(_v) => _v,
        None => return false,
    };

    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    let keypair = schnorr.new_keypair(p);

    let msg = unsafe { Vec::from_raw_parts(msg_bytes, msg_size, msg_size) };
    let message = Message::<Public>::raw(&msg);

    let signature = schnorr.sign(&keypair, message);

    let signature_bytes = signature.to_bytes();
    sig_bytes.copy_from_slice(&signature_bytes);

    let pub_bytes = keypair.public_key().into_bytes();
    pk_bytes.copy_from_slice(&pub_bytes);

    std::mem::forget(msg);

    return true;
}

#[no_mangle]
pub extern "C" fn schnorr_fun_schnorr_verify(msg_bytes: *mut u8, msg_size: libc::size_t, sig_bytes: &[u8; 64], pk_bytes: &[u8; 32]) -> bool {
    let nonce_gen = Deterministic::<Sha256>::default().add_tag("BIP0340");
    let signature = match Signature::<Public>::from_bytes(*sig_bytes) {
        Some(_v) => _v,
        None => return false,
    };

    let pubkey_x  = match XOnly::from_bytes(*pk_bytes) {
        Some(_v) => _v,
        None => return false,
    };
    let pubkey = pubkey_x.to_point();


    let msg = unsafe { Vec::from_raw_parts(msg_bytes, msg_size, msg_size) };
    let message = Message::<Public>::raw(&msg);

    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    let ret = schnorr.verify(&pubkey, message, &signature);

    std::mem::forget(msg);

    return ret;
}
