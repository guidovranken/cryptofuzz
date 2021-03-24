use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::num::NonZeroU32;
use std::os::raw::c_char;
use std::ptr::NonNull;

use p256;
use ring::aead;
use ring::aead::BoundKey;
use ring::digest;
use ring::hkdf;
use ring::hmac;
use ring::pbkdf2;
use ring::signature;
use ring::signature::VerificationAlgorithm;
use serde::de::{self, Deserialize, Deserializer};
use serde::Serializer;
use serde_derive::{Deserialize, Serialize};

mod ids;
use crate::ids::{CipherType, CurveType, DigestType};

impl TryInto<hmac::Algorithm> for DigestType {
    type Error = &'static str;

    fn try_into(self) -> Result<hmac::Algorithm, Self::Error> {
        match self {
            DigestType::SHA1 => Ok(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::SHA256 => Ok(hmac::HMAC_SHA256),
            DigestType::SHA384 => Ok(hmac::HMAC_SHA384),
            DigestType::SHA512 => Ok(hmac::HMAC_SHA512),
            _ => return Err("digest not available"),
        }
    }
}

impl TryInto<&'static digest::Algorithm> for DigestType {
    type Error = &'static str;

    fn try_into(self) -> Result<&'static digest::Algorithm, Self::Error> {
        match self {
            DigestType::SHA1 => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::SHA256 => Ok(&digest::SHA256),
            DigestType::SHA384 => Ok(&digest::SHA384),
            DigestType::SHA512 => Ok(&digest::SHA512),
            DigestType::SHA512_256 => Ok(&digest::SHA512_256),
            _ => return Err("digest not available"),
        }
    }
}

impl TryInto<pbkdf2::Algorithm> for DigestType {
    type Error = &'static str;

    fn try_into(self) -> Result<pbkdf2::Algorithm, Self::Error> {
        match self {
            DigestType::SHA1 => Ok(pbkdf2::PBKDF2_HMAC_SHA1),
            DigestType::SHA256 => Ok(pbkdf2::PBKDF2_HMAC_SHA256),
            DigestType::SHA384 => Ok(pbkdf2::PBKDF2_HMAC_SHA384),
            DigestType::SHA512 => Ok(pbkdf2::PBKDF2_HMAC_SHA512),
            _ => return Err("digest not available"),
        }
    }
}

impl TryInto<hkdf::Algorithm> for DigestType {
    type Error = &'static str;

    fn try_into(self) -> Result<hkdf::Algorithm, Self::Error> {
        match self {
            DigestType::SHA1 => Ok(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::SHA256 => Ok(hkdf::HKDF_SHA256),
            DigestType::SHA384 => Ok(hkdf::HKDF_SHA384),
            DigestType::SHA512 => Ok(hkdf::HKDF_SHA512),
            _ => return Err("digest not available"),
        }
    }
}

impl TryInto<&'static aead::Algorithm> for CipherType {
    type Error = &'static str;

    fn try_into(self) -> Result<&'static aead::Algorithm, Self::Error> {
        match self {
            CipherType::AES_128_GCM => Ok(&aead::AES_128_GCM),
            CipherType::AES_256_GCM => Ok(&aead::AES_256_GCM),
            CipherType::CHACHA20_POLY1305 => Ok(&aead::CHACHA20_POLY1305),
            _ => return Err("cipher not available"),
        }
    }
}

fn digest_type_from_str<'de, D>(deserializer: D) -> Result<DigestType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(de::Error::custom)
}

fn cipher_type_from_str<'de, D>(deserializer: D) -> Result<CipherType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(de::Error::custom)
}

fn curve_type_from_str<'de, D>(deserializer: D) -> Result<CurveType, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(de::Error::custom)
}

fn digest_type_to_str<S>(t: &DigestType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let t = serde_json::to_string(t).unwrap();
    serializer.serialize_str(&t)
}

fn cipher_type_to_str<S>(t: &CipherType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let t = serde_json::to_string(t).unwrap();
    serializer.serialize_str(&t)
}

fn curve_type_to_str<S>(t: &CurveType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let t = serde_json::to_string(t).unwrap();
    serializer.serialize_str(&t)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpDigest {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpHMAC {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    cipher: SymmetricCipher,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SymmetricCipher {
    #[serde(with = "hex_serde")]
    iv: Vec<u8>,
    #[serde(with = "hex_serde")]
    key: Vec<u8>,
    #[serde(
        serialize_with = "cipher_type_to_str",
        deserialize_with = "cipher_type_from_str"
    )]
    cipher_type: CipherType,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(non_camel_case_types)]
struct OpKDF_HKDF {
    #[serde(
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    #[serde(with = "hex_serde")]
    password: Vec<u8>,
    #[serde(with = "hex_serde")]
    salt: Vec<u8>,
    #[serde(with = "hex_serde")]
    info: Vec<u8>,
    key_size: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(non_camel_case_types)]
struct OpKDF_PBKDF2 {
    #[serde(
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    #[serde(with = "hex_serde")]
    password: Vec<u8>,
    #[serde(with = "hex_serde")]
    salt: Vec<u8>,
    iterations: u64,
    key_size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpSymmetricEncrypt {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(with = "hex_serde")]
    #[serde(default)]
    aad: Vec<u8>,
    cipher: SymmetricCipher,
    ciphertext_size: u64,
    tag_size: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpSymmetricDecrypt {
    #[serde(with = "hex_serde")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex_serde")]
    #[serde(default)]
    aad: Vec<u8>,
    #[serde(with = "hex_serde")]
    #[serde(default)]
    tag: Vec<u8>,
    cipher: SymmetricCipher,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpSign {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    #[serde(
        serialize_with = "curve_type_to_str",
        deserialize_with = "curve_type_from_str"
    )]
    curve_type: CurveType,
    #[serde(with = "hex_serde")]
    pkey_pem: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OpECDSASign {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(rename = "priv")]
    priv_key: String,
    #[serde(
        rename = "digestType",
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    #[serde(
        rename = "curveType",
        serialize_with = "curve_type_to_str",
        deserialize_with = "curve_type_from_str"
    )]
    curve_type: CurveType,
    nonce: String, // bignum
    nonce_source: i8,
}

#[derive(Serialize, Deserialize, Debug)]
struct OpECDSAVerify {
    #[serde(with = "hex_serde")]
    cleartext: Vec<u8>,
    #[serde(
        rename = "digestType",
        serialize_with = "digest_type_to_str",
        deserialize_with = "digest_type_from_str"
    )]
    digest_type: DigestType,
    #[serde(
        rename = "curveType",
        serialize_with = "curve_type_to_str",
        deserialize_with = "curve_type_from_str"
    )]
    curve_type: CurveType,
    pub_x: String,
    pub_y: String,
    sig_r: String,
    sig_s: String,
}

#[repr(C)]
pub struct Buffer {
    pub bytes: *mut u8,
    pub len: libc::size_t,
}

impl Buffer {
    pub fn new(slice: &[u8]) -> Self {
        let mut bytes = slice.to_vec();
        assert!(bytes.len() == bytes.capacity());
        let buf = Buffer {
            bytes: bytes.as_mut_ptr(),
            len: bytes.len(),
        };
        std::mem::forget(bytes);
        buf
    }

    pub fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }

    pub unsafe fn from_raw(raw: *mut Self) -> Box<Self> {
        Box::from_raw(raw)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(self.bytes, self.len, self.len);
        }
    }
}

pub struct Buffers {
    pub bufs: *mut Buffer,
    pub len: libc::size_t,
}

impl Buffers {
    pub fn new(mut buffers: Vec<Buffer>) -> Self {
        assert!(buffers.len() == buffers.capacity());
        let bufs = Buffers {
            bufs: buffers.as_mut_ptr(),
            len: buffers.len(),
        };
        std::mem::forget(buffers);
        bufs
    }

    pub fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }

    pub unsafe fn from_raw(raw: *mut Self) -> Box<Self> {
        Box::from_raw(raw)
    }
}

impl Drop for Buffers {
    fn drop(&mut self) {
        unsafe {
            Vec::from_raw_parts(self.bufs, self.len, self.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn free_buf(p: *mut Buffer) {
    unsafe {
        Buffer::from_raw(p);
    };
}

#[no_mangle]
pub extern "C" fn free_bufs(p: *mut Buffers) {
    unsafe {
        Buffers::from_raw(p);
    };
}

#[no_mangle]
pub extern "C" fn digest(op_json: *const c_char) -> Option<NonNull<Buffer>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let op: OpDigest = serde_json::from_str(serialized).ok()?;
    let algorithm = op.digest_type.try_into().ok()?;
    let res = digest::digest(algorithm, &op.cleartext);
    NonNull::new(Buffer::new(res.as_ref()).into_raw())
}

#[no_mangle]
pub extern "C" fn hmac(op_json: *const c_char) -> Option<NonNull<Buffer>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let op: OpHMAC = serde_json::from_str(serialized).ok()?;
    let algorithm = op.digest_type.try_into().ok()?;
    let key = hmac::Key::new(algorithm, &op.cipher.key);
    let res = hmac::sign(&key, &op.cleartext);
    NonNull::new(Buffer::new(res.as_ref()).into_raw())
}

#[no_mangle]
pub extern "C" fn kdf_hkdf(op_json: *const c_char) -> Option<NonNull<Buffer>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let op: OpKDF_HKDF = serde_json::from_str(serialized).ok()?;
    let algorithm = op.digest_type.try_into().ok()?;

    let salt = hkdf::Salt::new(algorithm, &op.salt);
    let prk = salt.extract(&op.password);
    let infos = vec![&op.info[..]];
    let okm = prk.expand(&infos[..], algorithm).unwrap();

    let mut bytes = vec![0; op.key_size as usize];
    okm.fill(&mut bytes).ok()?;
    NonNull::new(Buffer::new(&bytes[..]).into_raw())
}

#[no_mangle]
pub extern "C" fn kdf_pbkdf2(op_json: *const c_char) -> Option<NonNull<Buffer>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let op: OpKDF_PBKDF2 = serde_json::from_str(serialized).ok()?;
    let algorithm = op.digest_type.try_into().ok()?;

    let iterations = NonZeroU32::new(u32::try_from(op.iterations).ok()?)?;

    let mut bytes = vec![0; op.key_size as usize];
    pbkdf2::derive(algorithm, iterations, &op.salt, &op.password, &mut bytes);
    NonNull::new(Buffer::new(&bytes[..]).into_raw())
}

struct OneNonce {
    iv: Option<[u8; aead::NONCE_LEN]>,
}

impl<'a> aead::NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.iv
            .take()
            .map(|iv| aead::Nonce::assume_unique_for_key(iv))
            .ok_or_else(|| ring::error::Unspecified)
    }
}

#[no_mangle]
pub extern "C" fn symmetric_encrypt(op_json: *const c_char) -> Option<NonNull<Buffers>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let mut op: OpSymmetricEncrypt = serde_json::from_str(serialized).ok()?;

    let algorithm: &aead::Algorithm = op.cipher.cipher_type.try_into().ok()?;
    let aad = aead::Aad::from(op.aad);

    // Tag is always 128 bit in ring
    let tag_size = op.tag_size.unwrap_or(0) as usize;
    if tag_size != 16 {
        return None;
    }

    // IV must be 12 bytes. return None otherwise!
    let nonce = OneNonce {
        iv: Some(op.cipher.iv.try_into().ok()?),
    };

    let unbound_key = aead::UnboundKey::new(algorithm, &op.cipher.key[..]).ok()?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce);
    let tag = sealing_key
        .seal_in_place_separate_tag(aad, &mut op.cleartext)
        .expect("failed to encrypt");

    let ciphertext = Buffer::new(&op.cleartext[..]);
    let tag = Buffer::new(tag.as_ref());

    NonNull::new(Buffers::new(vec![ciphertext, tag]).into_raw())
}

#[no_mangle]
pub extern "C" fn symmetric_decrypt(op_json: *const c_char) -> Option<NonNull<Buffer>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let mut op: OpSymmetricDecrypt = serde_json::from_str(serialized).ok()?;

    let algorithm = op.cipher.cipher_type.try_into().ok()?;
    let aad = aead::Aad::from(op.aad);

    // IV must be 12 bytes. return None otherwise!
    let nonce = OneNonce {
        iv: Some(op.cipher.iv.try_into().ok()?),
    };

    let unbound_key = aead::UnboundKey::new(algorithm, &op.cipher.key[..]).ok()?;
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce);
    op.ciphertext.extend_from_slice(&op.tag[..]);
    let cleartext = opening_key.open_in_place(aad, &mut op.ciphertext).ok()?;

    NonNull::new(Buffer::new(cleartext).into_raw())
}

#[no_mangle]
pub extern "C" fn ecdsa_sign(op_json: *const c_char) -> Option<NonNull<Buffers>> {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();

    let op: OpECDSASign = serde_json::from_str(serialized).ok()?;

    // ring alawys uses a random source.
    if op.nonce_source != 0 {
        return None;
    }

    let (algo, sz) = match (op.curve_type, op.digest_type) {
        (CurveType::x962_p256v1, DigestType::SHA256) => {
            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, 32)
        }
        (CurveType::secp256r1, DigestType::SHA256) => {
            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, 32)
        }
        // p384 package is missing arithmetic feature to get pub key bytes from private key
        // CurveType::secp384r1 => (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, 48),
        _ => return None,
    };

    let sk_bytes = str_number_to_be_bytes(&op.priv_key, sz)?;

    // Ring does not seem to have a way to recover the public key from the private key. Rely on
    // p256 package instead.
    let sk = p256::SecretKey::from_bytes(&sk_bytes[..]).ok()?;
    let pk = sk.public_key();
    let pt: p256::EncodedPoint = pk.as_affine().to_owned().into();
    let pk_bytes = pt.as_bytes();

    let signer = signature::EcdsaKeyPair::from_private_key_and_public_key(
        algo,
        &sk_bytes[..],
        &pk_bytes[..],
    )
    .ok()?;
    let rand = ring::rand::SystemRandom::new();
    let sig = signer
        .sign(&rand, &op.cleartext[..])
        .expect("sign should fail");
    let sig = Buffer::new(sig.as_ref());
    let pk = Buffer::new(&pk_bytes[..]);
    NonNull::new(Buffers::new(vec![sig, pk]).into_raw())
}

// Takes a string decimal number and returns padded bytes in big endian
fn str_number_to_be_bytes(str_num: &str, output_len: usize) -> Option<Vec<u8>> {
    if str_num.is_empty() {
        return Some(vec![0; output_len]);
    }
    let mut bytes = num_bigint::BigUint::parse_bytes(str_num.as_bytes(), 10)
        .unwrap()
        .to_bytes_be();
    if bytes.len() > output_len {
        return None;
    }
    // left-pad, if necessary
    bytes.splice(0..0, vec![0; output_len - bytes.len()]);
    Some(bytes)
}

// -1 is skip
// 0 is failed verify
// 1 is valid verify
#[no_mangle]
pub extern "C" fn ecdsa_verify(op_json: *const c_char) -> i8 {
    let serialized = unsafe { CStr::from_ptr(op_json) }.to_str().unwrap();
    let op: OpECDSAVerify = match serde_json::from_str(serialized) {
        Ok(op) => op,
        Err(_) => return -1,
    };

    let (algo, sz) = match (op.curve_type, op.digest_type) {
        (CurveType::x962_p256v1, DigestType::SHA256) => (&signature::ECDSA_P256_SHA256_FIXED, 32),
        (CurveType::secp256r1, DigestType::SHA256) => (&signature::ECDSA_P256_SHA256_FIXED, 32),
        (CurveType::secp384r1, DigestType::SHA384) => (&signature::ECDSA_P384_SHA384_FIXED, 48),
        _ => return -1,
    };

    let public_key = {
        let x_bytes = match str_number_to_be_bytes(&op.pub_x, sz) {
            Some(bs) => bs,
            None => return -1,
        };
        let y_bytes = match str_number_to_be_bytes(&op.pub_y, sz) {
            Some(bs) => bs,
            None => return -1,
        };
        let mut public_key = vec![4u8];
        public_key.extend(x_bytes);
        public_key.extend(y_bytes);
        public_key
    };

    let signature = {
        let mut r_bytes = match str_number_to_be_bytes(&op.sig_r, sz) {
            Some(bs) => bs,
            None => return -1,
        };
        let s_bytes = match str_number_to_be_bytes(&op.sig_s, sz) {
            Some(bs) => bs,
            None => return -1,
        };
        r_bytes.extend(s_bytes);
        r_bytes
    };

    if algo
        .verify(
            (&public_key[..]).into(),
            (&op.cleartext[..]).into(),
            (&signature[..]).into(),
        )
        .is_ok()
    {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand_core::OsRng;

    #[test]
    fn test_deser() {
        let op: OpDigest =
            serde_json::from_str(r#"{"cleartext": "41", "digestType": "2824928280559055109"}"#)
                .unwrap();
        assert_eq!(op.cleartext, vec![0x41]);
        assert_eq!(op.digest_type, DigestType::GOST_28147_89);

        let op: OpHMAC = serde_json::from_str(
            r#"{"cleartext": "", "digestType": "2824928280559055109", "cipher": {"iv": "", "key": "", "cipherType": "168239428651064518"}}"#,
        )
        .unwrap();
        assert_eq!(op.cipher.cipher_type, CipherType::AES_256_ECB);
    }

    #[test]
    fn test_aead() {
        // Encrypt
        let encrypt_request = OpSymmetricEncrypt {
            cleartext: "HI".into(),
            aad: vec![],
            cipher: SymmetricCipher {
                iv: vec![1; 12],
                key: vec![0x41; 16],
                cipher_type: CipherType::AES_128_GCM,
            },
            ciphertext_size: 0, // unused
            tag_size: Some(16),
        };

        let op_json =
            serde_json::to_string(&encrypt_request).expect("encrypt request should be valid");
        let cstring = std::ffi::CString::new(op_json).unwrap();
        let op_json_ptr = cstring.as_c_str().as_ptr();
        let buffers = unsafe {
            Buffers::from_raw(
                symmetric_encrypt(op_json_ptr)
                    .expect("valid encryption")
                    .as_ptr(),
            )
        };

        let bufs = unsafe { Vec::from_raw_parts(buffers.bufs, buffers.len, buffers.len) };
        let ciphertext = unsafe { Vec::from_raw_parts(bufs[0].bytes, bufs[0].len, bufs[0].len) };
        let tag = unsafe { Vec::from_raw_parts(bufs[1].bytes, bufs[1].len, bufs[1].len) };

        // Avoid double frees (this might leak mem, but doesn't matter in test)
        std::mem::forget(buffers);
        std::mem::forget(bufs);

        // Decrypt
        let decrypt_request = OpSymmetricDecrypt {
            ciphertext,
            aad: vec![],
            tag,
            cipher: SymmetricCipher {
                iv: vec![1; 12],
                key: vec![0x41; 16],
                cipher_type: CipherType::AES_128_GCM,
            },
        };

        let op_json =
            serde_json::to_string(&decrypt_request).expect("decrypt request should be valid");
        let cstring = std::ffi::CString::new(op_json).unwrap();
        let op_json_ptr = cstring.as_c_str().as_ptr();
        let buffer = unsafe {
            Buffer::from_raw(
                symmetric_decrypt(op_json_ptr)
                    .expect("valid decryption")
                    .as_ptr(),
            )
        };
        let cleartext = unsafe { Vec::from_raw_parts(buffer.bytes, buffer.len, buffer.len) };
        // Avoid double frees (this might leak mem, but doesn't matter in test)
        std::mem::forget(buffer);

        assert_eq!(cleartext, encrypt_request.cleartext);
    }

    #[test]
    fn test_ecdsa() {
        // Generate public key
        let sk = p256::SecretKey::random(OsRng);
        let priv_key = num_bigint::BigUint::from_bytes_be(&sk.to_bytes()).to_str_radix(10);

        // Sign
        let sign_request = OpECDSASign {
            cleartext: "HI".into(),
            priv_key,
            digest_type: DigestType::SHA256,
            curve_type: CurveType::x962_p256v1,
            nonce: "".to_string(), // bignum
            nonce_source: 0,
        };
        let op_json = serde_json::to_string(&sign_request).expect("sign request should be valid");
        let cstring = std::ffi::CString::new(op_json).unwrap();
        let op_json_ptr = cstring.as_c_str().as_ptr();
        let buffers = unsafe {
            Buffers::from_raw(ecdsa_sign(op_json_ptr).expect("valid signature").as_ptr())
        };

        let bufs = unsafe { Vec::from_raw_parts(buffers.bufs, buffers.len, buffers.len) };
        let sig = unsafe { Vec::from_raw_parts(bufs[0].bytes, bufs[0].len, bufs[0].len) };
        let pk = unsafe { Vec::from_raw_parts(bufs[1].bytes, bufs[1].len, bufs[1].len) };

        // Avoid double frees (this might leak mem, but doesn't matter in test)
        std::mem::forget(buffers);
        std::mem::forget(bufs);

        // Verify public key returned
        let real_pk = sk.public_key();
        assert_eq!(sig.len(), 64);
        assert_eq!(pk.len(), 65);
        assert_eq!(real_pk, p256::PublicKey::from_sec1_bytes(&pk[..]).unwrap());

        // Verify valid signature
        let mut verify_request = OpECDSAVerify {
            cleartext: "HI".into(),
            digest_type: DigestType::SHA256,
            curve_type: CurveType::x962_p256v1,
            pub_x: num_bigint::BigUint::from_bytes_be(&pk[1..1 + 32]).to_str_radix(10),
            pub_y: num_bigint::BigUint::from_bytes_be(&pk[1 + 32..1 + 32 + 32]).to_str_radix(10),
            sig_r: num_bigint::BigUint::from_bytes_be(&sig[0..32]).to_str_radix(10),
            sig_s: num_bigint::BigUint::from_bytes_be(&sig[32..64]).to_str_radix(10),
        };

        let op_json =
            serde_json::to_string(&verify_request).expect("verify request should be valid");
        let cstring = std::ffi::CString::new(op_json).unwrap();
        let op_json_ptr = cstring.as_c_str().as_ptr();
        let res = ecdsa_verify(op_json_ptr);
        assert_eq!(res, 1);

        // Verify invalid signature
        verify_request.cleartext = "BAD".into();

        let op_json =
            serde_json::to_string(&verify_request).expect("verify request should be valid");
        let cstring = std::ffi::CString::new(op_json).unwrap();
        let op_json_ptr = cstring.as_c_str().as_ptr();
        let res = ecdsa_verify(op_json_ptr);
        assert_eq!(res, 0);
    }
}
