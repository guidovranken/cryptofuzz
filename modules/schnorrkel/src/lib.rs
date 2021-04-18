use schnorrkel::{PublicKey, Signature};

use std::os::raw::c_ulong;
use std::slice;

const SIGNING_CTX: &'static [u8] = b"substrate";

#[no_mangle]
pub unsafe extern "C" fn sr25519_verify(
    sig_bytes: &[u8; 64],
    pk_bytes: &[u8; 32],
    message_ptr: *const u8,
    message_length: c_ulong,
) -> bool {
    let message = slice::from_raw_parts(message_ptr, message_length as usize);
    let signature = match Signature::from_bytes(sig_bytes) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(public) => public,
        Err(_) => return false,
    };

    pk.verify_simple(SIGNING_CTX, message, &signature).is_ok()
}

