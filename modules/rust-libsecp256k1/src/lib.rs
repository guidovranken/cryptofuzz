use libsecp256k1::{SecretKey, PublicKey, Signature, Message, verify, sign};

#[no_mangle]
pub extern "C" fn ecc_privatetopublic(sk_bytes: &[u8; 32], pk_bytes: &mut [u8; 65]) -> bool {
    let sk = match SecretKey::parse(sk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    let pk = PublicKey::from_secret_key(&sk);
    pk_bytes.copy_from_slice(&pk.serialize());
    return true;
}

#[no_mangle]
pub extern "C" fn ecdsa_verify(msg_bytes: &[u8; 32], sig_bytes: &[u8; 64], pk_bytes: &[u8; 65]) -> bool {
    let msg = Message::parse(msg_bytes);
    let sig = Signature::parse(sig_bytes);
    let pk = match PublicKey::parse(pk_bytes) {
        Ok(_v) => _v,
        Err(_e) => return false,
    };
    return verify(&msg, &sig, &pk);
}

#[no_mangle]
pub extern "C" fn ecdsa_sign(msg_bytes: &[u8; 32], sk_bytes: &[u8; 32], sig_bytes: &mut [u8; 64]) -> bool {
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
pub extern "C" fn validate_pubkey(pk_bytes: &[u8; 65]) -> bool {
    match PublicKey::parse(pk_bytes) {
        Ok(_v) => true,
        Err(_e) => false,
    }
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
