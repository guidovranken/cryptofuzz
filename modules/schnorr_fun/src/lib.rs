use schnorr_fun::{
    fun::{marker::*, nonce, XOnly},
    Schnorr,
    Message,
    Signature
};

use sha2::Sha256;
use rand::rngs::ThreadRng;

#[no_mangle]
pub extern "C" fn schnorr_fun_schnorr_verify(msg_bytes: *mut u8, msg_size: libc::size_t, sig_bytes: &[u8; 64], pk_bytes: &[u8; 32]) -> bool {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
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
