use std::slice;
use std::ptr;

use sha2::{Sha224, Sha256, Sha384, Sha512, Digest};
use sha1::{Sha1};
use streebog::{Streebog256, Streebog512};
use whirlpool::{Whirlpool};
use ripemd160::{Ripemd160};
use ripemd256::{Ripemd256};
use ripemd320::{Ripemd320};
use sm3::{Sm3};
use gost94::{Gost94CryptoPro};
use md2::{Md2};
use md4::{Md4};
use md5::{Md5};
use groestl::{Groestl224, Groestl256, Groestl384, Groestl512};
use tiger::{Tiger};
use blake2::{Blake2b, Blake2s};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512};
use fsb::{Fsb160, Fsb224, Fsb256, Fsb384, Fsb512};
use shabal::{Shabal256, Shabal512};

use digest::{BlockInput, FixedOutput, Reset, Update};
use hkdf::Hkdf;

use hmac::{Mac, Hmac, NewMac};

use scrypt::{scrypt, Params as ScryptParams};

use crypto_bigint::{U256, Encoding, Integer, Zero};

use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
};

use aes::Aes128;
use cmac::Cmac;

use std::convert::TryInto;
mod ids;
use crate::ids::{*};

fn create_parts(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t) -> Vec<Vec<u8>> {
    let input = unsafe { slice::from_raw_parts(input_bytes, input_size) };
    let parts = unsafe { slice::from_raw_parts(parts_bytes, parts_size) };
    let mut ret : Vec<Vec<u8>> = Vec::new();

    let mut pos = 0;
    for part in parts.iter() {
        ret.push(input[pos..(pos + *part)].to_vec());
        pos += part;
    }

    return ret;
}

fn hash<D: Digest>(parts: Vec<Vec<u8>>, out: *mut u8) -> i32 {
    let mut hasher = D::new();

    for part in parts.iter() {
        hasher.update(part);
    }

    let res = hasher.finalize();

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return res.len().try_into().unwrap();
}

#[no_mangle]
pub extern "C" fn rustcrypto_hashes_hash(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);

         if is_sha1(algorithm)            { return hash::<Sha1>(parts, out); }
    else if is_sha224(algorithm)          { return hash::<Sha224>(parts, out); }
    else if is_sha256(algorithm)          { return hash::<Sha256>(parts, out); }
    else if is_sha384(algorithm)          { return hash::<Sha384>(parts, out); }
    else if is_sha512(algorithm)          { return hash::<Sha512>(parts, out); }
    else if is_streebog_256(algorithm)    { return hash::<Streebog256>(parts, out); }
    else if is_streebog_512(algorithm)    { return hash::<Streebog512>(parts, out); }
    else if is_whirlpool(algorithm)       { return hash::<Whirlpool>(parts, out); }
    else if is_ripemd160(algorithm)       { return hash::<Ripemd160>(parts, out); }
    else if is_ripemd256(algorithm)       { return hash::<Ripemd256>(parts, out); }
    else if is_ripemd320(algorithm)       { return hash::<Ripemd320>(parts, out); }
    else if is_gost_r_34_11_94(algorithm) { return hash::<Gost94CryptoPro>(parts, out); }
    else if is_sm3(algorithm)             { return hash::<Sm3>(parts, out); }
    else if is_md2(algorithm)             { return hash::<Md2>(parts, out); }
    else if is_md4(algorithm)             { return hash::<Md4>(parts, out); }
    else if is_md5(algorithm)             { return hash::<Md5>(parts, out); }
    else if is_groestl_224(algorithm)     { return hash::<Groestl224>(parts, out); }
    else if is_groestl_256(algorithm)     { return hash::<Groestl256>(parts, out); }
    else if is_groestl_384(algorithm)     { return hash::<Groestl384>(parts, out); }
    else if is_groestl_512(algorithm)     { return hash::<Groestl512>(parts, out); }
    else if is_blake2b512(algorithm)      { return hash::<Blake2b>(parts, out); }
    else if is_blake2s256(algorithm)      { return hash::<Blake2s>(parts, out); }
    else if is_sha3_224(algorithm)        { return hash::<Sha3_224>(parts, out); }
    else if is_sha3_256(algorithm)        { return hash::<Sha3_256>(parts, out); }
    else if is_sha3_384(algorithm)        { return hash::<Sha3_384>(parts, out); }
    else if is_sha3_512(algorithm)        { return hash::<Sha3_512>(parts, out); }
    else if is_keccak_224(algorithm)      { return hash::<Keccak224>(parts, out); }
    else if is_keccak_256(algorithm)      { return hash::<Keccak256>(parts, out); }
    else if is_keccak_384(algorithm)      { return hash::<Keccak384>(parts, out); }
    else if is_keccak_512(algorithm)      { return hash::<Keccak512>(parts, out); }
    else if is_fsb_160(algorithm)         { return hash::<Fsb160>(parts, out); }
    else if is_fsb_224(algorithm)         { return hash::<Fsb224>(parts, out); }
    else if is_fsb_256(algorithm)         { return hash::<Fsb256>(parts, out); }
    else if is_fsb_384(algorithm)         { return hash::<Fsb384>(parts, out); }
    else if is_fsb_512(algorithm)         { return hash::<Fsb512>(parts, out); }
    else if is_shabal_256(algorithm)      { return hash::<Shabal256>(parts, out); }
    else if is_shabal_512(algorithm)      { return hash::<Shabal512>(parts, out); }
    else if is_tiger(algorithm)           { return hash::<Tiger>(parts, out); }
    else {
        return -1;
    }
}

fn hkdf<D: BlockInput + Clone + Default + FixedOutput + Update + Reset>(
    password: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    keysize: u64,
    out: *mut u8) -> i32 {

    let hk = Hkdf::<D>::new(Some(&salt), &password);
    let mut okm = vec![0u8; keysize.try_into().unwrap()];
    match hk.expand(&info, &mut okm) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };

    unsafe {
        ptr::copy_nonoverlapping(okm.as_ptr(), out, okm.len());
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rustcrypto_hkdf(
    password_bytes: *const u8, password_size: libc::size_t,
    salt_bytes: *const u8, salt_size: libc::size_t,
    info_bytes: *const u8, info_size: libc::size_t,
    keysize: u64,
    algorithm: u64,
    out: *mut u8) -> i32 {
    let password = unsafe { slice::from_raw_parts(password_bytes, password_size) }.to_vec();
    let salt = unsafe { slice::from_raw_parts(salt_bytes, salt_size) }.to_vec();
    let info = unsafe { slice::from_raw_parts(info_bytes, info_size) }.to_vec();

         if is_sha1(algorithm)            { return hkdf::<Sha1>(password, salt, info, keysize, out); }
    else if is_sha224(algorithm)          { return hkdf::<Sha224>(password, salt, info, keysize, out); }
    else if is_sha256(algorithm)          { return hkdf::<Sha256>(password, salt, info, keysize, out); }
    else if is_sha384(algorithm)          { return hkdf::<Sha384>(password, salt, info, keysize, out); }
    else if is_sha512(algorithm)          { return hkdf::<Sha512>(password, salt, info, keysize, out); }
    else if is_streebog_256(algorithm)    { return hkdf::<Streebog256>(password, salt, info, keysize, out); }
    else if is_streebog_512(algorithm)    { return hkdf::<Streebog512>(password, salt, info, keysize, out); }
    else if is_whirlpool(algorithm)       { return hkdf::<Whirlpool>(password, salt, info, keysize, out); }
    else if is_ripemd160(algorithm)       { return hkdf::<Ripemd160>(password, salt, info, keysize, out); }
    else if is_ripemd256(algorithm)       { return hkdf::<Ripemd256>(password, salt, info, keysize, out); }
    else if is_ripemd320(algorithm)       { return hkdf::<Ripemd320>(password, salt, info, keysize, out); }
    else if is_gost_r_34_11_94(algorithm) { return hkdf::<Gost94CryptoPro>(password, salt, info, keysize, out); }
    else if is_sm3(algorithm)             { return hkdf::<Sm3>(password, salt, info, keysize, out); }
    else if is_md2(algorithm)             { return hkdf::<Md2>(password, salt, info, keysize, out); }
    else if is_md4(algorithm)             { return hkdf::<Md4>(password, salt, info, keysize, out); }
    else if is_md5(algorithm)             { return hkdf::<Md5>(password, salt, info, keysize, out); }
    else if is_groestl_224(algorithm)     { return hkdf::<Groestl224>(password, salt, info, keysize, out); }
    else if is_groestl_256(algorithm)     { return hkdf::<Groestl256>(password, salt, info, keysize, out); }
    else if is_groestl_384(algorithm)     { return hkdf::<Groestl384>(password, salt, info, keysize, out); }
    else if is_groestl_512(algorithm)     { return hkdf::<Groestl512>(password, salt, info, keysize, out); }
    else if is_blake2b512(algorithm)      { return hkdf::<Blake2b>(password, salt, info, keysize, out); }
    else if is_blake2s256(algorithm)      { return hkdf::<Blake2s>(password, salt, info, keysize, out); }
    else if is_sha3_224(algorithm)        { return hkdf::<Sha3_224>(password, salt, info, keysize, out); }
    else if is_sha3_256(algorithm)        { return hkdf::<Sha3_256>(password, salt, info, keysize, out); }
    else if is_sha3_384(algorithm)        { return hkdf::<Sha3_384>(password, salt, info, keysize, out); }
    else if is_sha3_512(algorithm)        { return hkdf::<Sha3_512>(password, salt, info, keysize, out); }
    else if is_keccak_224(algorithm)      { return hkdf::<Keccak224>(password, salt, info, keysize, out); }
    else if is_keccak_256(algorithm)      { return hkdf::<Keccak256>(password, salt, info, keysize, out); }
    else if is_keccak_384(algorithm)      { return hkdf::<Keccak384>(password, salt, info, keysize, out); }
    else if is_keccak_512(algorithm)      { return hkdf::<Keccak512>(password, salt, info, keysize, out); }
    else if is_fsb_160(algorithm)         { return hkdf::<Fsb160>(password, salt, info, keysize, out); }
    else if is_fsb_224(algorithm)         { return hkdf::<Fsb224>(password, salt, info, keysize, out); }
    else if is_fsb_256(algorithm)         { return hkdf::<Fsb256>(password, salt, info, keysize, out); }
    else if is_fsb_384(algorithm)         { return hkdf::<Fsb384>(password, salt, info, keysize, out); }
    else if is_fsb_512(algorithm)         { return hkdf::<Fsb512>(password, salt, info, keysize, out); }
    else if is_shabal_256(algorithm)      { return hkdf::<Shabal256>(password, salt, info, keysize, out); }
    else if is_shabal_512(algorithm)      { return hkdf::<Shabal512>(password, salt, info, keysize, out); }
    else if is_tiger(algorithm)           { return hkdf::<Tiger>(password, salt, info, keysize, out); }
    else {
        return -1;
    }
}

fn hmac<D: BlockInput + Clone + Default + FixedOutput + Update + Reset>(
    parts: Vec<Vec<u8>>,
    key: Vec<u8>,
    out: *mut u8) -> i32 {

    let mut hmac = match Hmac::<D>::new_from_slice(&key) {
        Ok(_v) => _v,
        Err(_e) => return -1,
    };

    for part in parts.iter() {
        hmac.update(part);
    }

    let res = hmac.finalize().into_bytes();

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return res.len().try_into().unwrap();
}

#[no_mangle]
pub extern "C" fn rustcrypto_hmac(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let key = unsafe { slice::from_raw_parts(key_bytes, key_size) }.to_vec();

         if is_sha1(algorithm)            { return hmac::<Sha1>(parts, key, out); }
    else if is_sha224(algorithm)          { return hmac::<Sha224>(parts, key, out); }
    else if is_sha256(algorithm)          { return hmac::<Sha256>(parts, key, out); }
    else if is_sha384(algorithm)          { return hmac::<Sha384>(parts, key, out); }
    else if is_sha512(algorithm)          { return hmac::<Sha512>(parts, key, out); }
    else if is_streebog_256(algorithm)    { return hmac::<Streebog256>(parts, key, out); }
    else if is_streebog_512(algorithm)    { return hmac::<Streebog512>(parts, key, out); }
    else if is_whirlpool(algorithm)       { return hmac::<Whirlpool>(parts, key, out); }
    else if is_ripemd160(algorithm)       { return hmac::<Ripemd160>(parts, key, out); }
    else if is_ripemd256(algorithm)       { return hmac::<Ripemd256>(parts, key, out); }
    else if is_ripemd320(algorithm)       { return hmac::<Ripemd320>(parts, key, out); }
    else if is_gost_r_34_11_94(algorithm) { return hmac::<Gost94CryptoPro>(parts, key, out); }
    else if is_sm3(algorithm)             { return hmac::<Sm3>(parts, key, out); }
    else if is_md2(algorithm)             { return hmac::<Md2>(parts, key, out); }
    else if is_md4(algorithm)             { return hmac::<Md4>(parts, key, out); }
    else if is_md5(algorithm)             { return hmac::<Md5>(parts, key, out); }
    else if is_groestl_224(algorithm)     { return hmac::<Groestl224>(parts, key, out); }
    else if is_groestl_256(algorithm)     { return hmac::<Groestl256>(parts, key, out); }
    else if is_groestl_384(algorithm)     { return hmac::<Groestl384>(parts, key, out); }
    else if is_groestl_512(algorithm)     { return hmac::<Groestl512>(parts, key, out); }
    else if is_blake2b512(algorithm)      { return hmac::<Blake2b>(parts, key, out); }
    else if is_blake2s256(algorithm)      { return hmac::<Blake2s>(parts, key, out); }
    else if is_sha3_224(algorithm)        { return hmac::<Sha3_224>(parts, key, out); }
    else if is_sha3_256(algorithm)        { return hmac::<Sha3_256>(parts, key, out); }
    else if is_sha3_384(algorithm)        { return hmac::<Sha3_384>(parts, key, out); }
    else if is_sha3_512(algorithm)        { return hmac::<Sha3_512>(parts, key, out); }
    else if is_keccak_224(algorithm)      { return hmac::<Keccak224>(parts, key, out); }
    else if is_keccak_256(algorithm)      { return hmac::<Keccak256>(parts, key, out); }
    else if is_keccak_384(algorithm)      { return hmac::<Keccak384>(parts, key, out); }
    else if is_keccak_512(algorithm)      { return hmac::<Keccak512>(parts, key, out); }
    else if is_fsb_160(algorithm)         { return hmac::<Fsb160>(parts, key, out); }
    else if is_fsb_224(algorithm)         { return hmac::<Fsb224>(parts, key, out); }
    else if is_fsb_256(algorithm)         { return hmac::<Fsb256>(parts, key, out); }
    else if is_fsb_384(algorithm)         { return hmac::<Fsb384>(parts, key, out); }
    else if is_fsb_512(algorithm)         { return hmac::<Fsb512>(parts, key, out); }
    else if is_shabal_256(algorithm)      { return hmac::<Shabal256>(parts, key, out); }
    else if is_shabal_512(algorithm)      { return hmac::<Shabal512>(parts, key, out); }
    else if is_tiger(algorithm)           { return hmac::<Tiger>(parts, key, out); }
    else {
        return -1;
    }
}

#[no_mangle]
pub extern "C" fn rustcrypto_scrypt(
    password_bytes: *const u8, password_size: libc::size_t,
    salt_bytes: *const u8, salt_size: libc::size_t,
    n: u8,
    r: u32,
    p: u32,
    keysize: u64,
    out: *mut u8) -> i32 {

    let password = unsafe { slice::from_raw_parts(password_bytes, password_size) }.to_vec();
    let salt = unsafe { slice::from_raw_parts(salt_bytes, salt_size) }.to_vec();

    let mut res = vec![0u8; keysize.try_into().unwrap()];

    let params = match ScryptParams::new(n, r, p)  {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    match scrypt(&password, &salt, &params, &mut res) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return 0;
}

fn pbkdf2_<D: Mac + NewMac + Clone + Sync>(
    password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    keysize: u64,
    out: *mut u8) -> i32 {

    let mut res = vec![0u8; keysize.try_into().unwrap()];

    pbkdf2::pbkdf2::<D>(&password, &salt, iterations, &mut res);

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rustcrypto_pbkdf2(
    password_bytes: *const u8, password_size: libc::size_t,
    salt_bytes: *const u8, salt_size: libc::size_t,
    iterations: u32,
    keysize: u64,
    algorithm: u64,
    out: *mut u8) -> i32 {

    let password = unsafe { slice::from_raw_parts(password_bytes, password_size) }.to_vec();
    let salt = unsafe { slice::from_raw_parts(salt_bytes, salt_size) }.to_vec();

         if is_sha1(algorithm)            { return pbkdf2_::<Hmac<Sha1>>(password, salt, iterations, keysize, out); }
    else if is_sha224(algorithm)          { return pbkdf2_::<Hmac<Sha224>>(password, salt, iterations, keysize, out); }
    else if is_sha256(algorithm)          { return pbkdf2_::<Hmac<Sha256>>(password, salt, iterations, keysize, out); }
    else if is_sha384(algorithm)          { return pbkdf2_::<Hmac<Sha384>>(password, salt, iterations, keysize, out); }
    else if is_sha512(algorithm)          { return pbkdf2_::<Hmac<Sha512>>(password, salt, iterations, keysize, out); }
    else if is_streebog_256(algorithm)    { return pbkdf2_::<Hmac<Streebog256>>(password, salt, iterations, keysize, out); }
    else if is_streebog_512(algorithm)    { return pbkdf2_::<Hmac<Streebog512>>(password, salt, iterations, keysize, out); }
    else if is_whirlpool(algorithm)       { return pbkdf2_::<Hmac<Whirlpool>>(password, salt, iterations, keysize, out); }
    else if is_ripemd160(algorithm)       { return pbkdf2_::<Hmac<Ripemd160>>(password, salt, iterations, keysize, out); }
    else if is_ripemd256(algorithm)       { return pbkdf2_::<Hmac<Ripemd256>>(password, salt, iterations, keysize, out); }
    else if is_ripemd320(algorithm)       { return pbkdf2_::<Hmac<Ripemd320>>(password, salt, iterations, keysize, out); }
    else if is_gost_r_34_11_94(algorithm) { return pbkdf2_::<Hmac<Gost94CryptoPro>>(password, salt, iterations, keysize, out); }
    else if is_sm3(algorithm)             { return pbkdf2_::<Hmac<Sm3>>(password, salt, iterations, keysize, out); }
    else if is_md2(algorithm)             { return pbkdf2_::<Hmac<Md2>>(password, salt, iterations, keysize, out); }
    else if is_md4(algorithm)             { return pbkdf2_::<Hmac<Md4>>(password, salt, iterations, keysize, out); }
    else if is_md5(algorithm)             { return pbkdf2_::<Hmac<Md5>>(password, salt, iterations, keysize, out); }
    else if is_groestl_224(algorithm)     { return pbkdf2_::<Hmac<Groestl224>>(password, salt, iterations, keysize, out); }
    else if is_groestl_256(algorithm)     { return pbkdf2_::<Hmac<Groestl256>>(password, salt, iterations, keysize, out); }
    else if is_groestl_384(algorithm)     { return pbkdf2_::<Hmac<Groestl384>>(password, salt, iterations, keysize, out); }
    else if is_groestl_512(algorithm)     { return pbkdf2_::<Hmac<Groestl512>>(password, salt, iterations, keysize, out); }
    else if is_blake2b512(algorithm)      { return pbkdf2_::<Hmac<Blake2b>>(password, salt, iterations, keysize, out); }
    else if is_blake2s256(algorithm)      { return pbkdf2_::<Hmac<Blake2s>>(password, salt, iterations, keysize, out); }
    else if is_sha3_224(algorithm)        { return pbkdf2_::<Hmac<Sha3_224>>(password, salt, iterations, keysize, out); }
    else if is_sha3_256(algorithm)        { return pbkdf2_::<Hmac<Sha3_256>>(password, salt, iterations, keysize, out); }
    else if is_sha3_384(algorithm)        { return pbkdf2_::<Hmac<Sha3_384>>(password, salt, iterations, keysize, out); }
    else if is_sha3_512(algorithm)        { return pbkdf2_::<Hmac<Sha3_512>>(password, salt, iterations, keysize, out); }
    else if is_keccak_224(algorithm)      { return pbkdf2_::<Hmac<Keccak224>>(password, salt, iterations, keysize, out); }
    else if is_keccak_256(algorithm)      { return pbkdf2_::<Hmac<Keccak256>>(password, salt, iterations, keysize, out); }
    else if is_keccak_384(algorithm)      { return pbkdf2_::<Hmac<Keccak384>>(password, salt, iterations, keysize, out); }
    else if is_keccak_512(algorithm)      { return pbkdf2_::<Hmac<Keccak512>>(password, salt, iterations, keysize, out); }
    else if is_fsb_160(algorithm)         { return pbkdf2_::<Hmac<Fsb160>>(password, salt, iterations, keysize, out); }
    else if is_fsb_224(algorithm)         { return pbkdf2_::<Hmac<Fsb224>>(password, salt, iterations, keysize, out); }
    else if is_fsb_256(algorithm)         { return pbkdf2_::<Hmac<Fsb256>>(password, salt, iterations, keysize, out); }
    else if is_fsb_384(algorithm)         { return pbkdf2_::<Hmac<Fsb384>>(password, salt, iterations, keysize, out); }
    else if is_fsb_512(algorithm)         { return pbkdf2_::<Hmac<Fsb512>>(password, salt, iterations, keysize, out); }
    else if is_shabal_256(algorithm)      { return pbkdf2_::<Hmac<Shabal256>>(password, salt, iterations, keysize, out); }
    else if is_shabal_512(algorithm)      { return pbkdf2_::<Hmac<Shabal512>>(password, salt, iterations, keysize, out); }
    else if is_tiger(algorithm)           { return pbkdf2_::<Hmac<Tiger>>(password, salt, iterations, keysize, out); }
    else {
        return -1;
    }
}

#[no_mangle]
pub extern "C" fn rustcrypto_bcrypt(
    password_bytes: *const u8, password_size: libc::size_t,
    salt_bytes: *const u8, salt_size: libc::size_t,
    iterations: u32,
    keysize: u64,
    out: *mut u8) -> i32 {

    let password = unsafe { slice::from_raw_parts(password_bytes, password_size) }.to_vec();
    let password = match std::str::from_utf8(&password) {
        Ok(_v) => (_v),
        Err(_e) => return -1,
    };

    let salt = unsafe { slice::from_raw_parts(salt_bytes, salt_size) }.to_vec();

    let mut res = vec![0u8; keysize.try_into().unwrap()];

    match bcrypt_pbkdf::bcrypt_pbkdf(password, &salt, iterations, &mut res) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rustcrypto_argon2(
    password_bytes: *const u8, password_size: libc::size_t,
    salt_bytes: *const u8, salt_size: libc::size_t,
    algorithm: u8,
    threads: u8,
    memory: u32,
    iterations: u32,
    keysize: u64,
    out: *mut u8) -> i32 {
    let password = unsafe { slice::from_raw_parts(password_bytes, password_size) }.to_vec();
    let salt = unsafe { slice::from_raw_parts(salt_bytes, salt_size) }.to_vec();

    let mut builder = ParamsBuilder::new();
    match builder.m_cost(memory) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };
    match builder.t_cost(iterations) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };
    match builder.p_cost(threads as u32) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };

    let params = match builder.params() {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    let mut res = vec![0u8; keysize.try_into().unwrap()];

    let algorithm = match algorithm {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        2 => Algorithm::Argon2id,
        _ => return -1,
    };

    let ctx = Argon2::new(algorithm, Version::V0x13, params);

    match ctx.hash_password_into(&password, &salt, &mut res) {
        Ok(_v) => (),
        Err(_e) => return -1,
    };

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rustcrypto_cmac(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let key = unsafe { slice::from_raw_parts(key_bytes, key_size) }.to_vec();

    let mut mac = match Cmac::<Aes128>::new_from_slice(&key) {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    for part in parts.iter() {
        mac.update(part);
    }

    let res = mac.finalize().into_bytes();

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return res.len() as i32;
}

#[no_mangle]
pub extern "C" fn rustcrypto_bigint_bignumcalc(
            op: u64,
            bn0: &[u8; 32],
            bn1: &[u8; 32],
            bn2: &[u8; 32],
            result: &mut [u8; 32]) -> i32 {
    let bn0 = U256::from_be_bytes(*bn0);
    let bn1 = U256::from_be_bytes(*bn1);
    let bn2 = U256::from_be_bytes(*bn2);

    let res: U256;
    if is_add(op) {
        res = bn0.wrapping_add(&bn1);
    } else if is_sub(op) {
        res = bn0.wrapping_sub(&bn1);
    } else if is_mul(op) {
        res = bn0.wrapping_mul(&bn1);
    } else if is_div(op) {
        if bool::from(bn1.is_zero()) {
            return -1;
        }
        res = bn0.wrapping_div(&bn1);
    } else if is_mod(op) {
        if bool::from(bn1.is_zero()) {
            return -1;
        }
        res = bn0.wrapping_rem(&bn1);
    } else if is_addmod(op) {
        res = bn0.add_mod(&bn1, &bn2);
    } else if is_submod(op) {
        res = bn0.sub_mod(&bn1, &bn2);
    } else if is_and(op) {
        res = bn0.wrapping_and(&bn1);
    } else if is_or(op) {
        res = bn0.wrapping_or(&bn1);
    } else if is_xor(op) {
        res = bn0.wrapping_xor(&bn1);
    } else if is_not(op) {
        res = bn0.not();
    } else if is_iseq(op) {
        res = if bn0 == bn1 { U256::ONE } else { U256::ZERO }
    } else if is_isgt(op) {
        res = if bn0 > bn1 { U256::ONE } else { U256::ZERO }
    } else if is_isgte(op) {
        res = if bn0 >= bn1 { U256::ONE } else { U256::ZERO }
    } else if is_islt(op) {
        res = if bn0 < bn1 { U256::ONE } else { U256::ZERO }
    } else if is_islte(op) {
        res = if bn0 <= bn1 { U256::ONE } else { U256::ZERO }
    } else if is_sqrt(op) {
        res = bn0.wrapping_sqrt();
    } else if is_iseven(op) {
        res = if bool::from(bn0.is_even()) { U256::ONE } else { U256::ZERO }
    } else if is_isodd(op) {
        res = if bool::from(bn0.is_odd()) { U256::ONE } else { U256::ZERO }
    } else if is_iszero(op) {
        res = if bool::from(bn0.is_zero()) { U256::ONE } else { U256::ZERO }
    } else if is_numbits(op) {
        res = (bn0.bits() as u64).into();
    } else if is_min(op) {
        res = bn0.min(bn1);
    } else if is_max(op) {
        res = bn0.max(bn1);
    } else {
        return -1;
    }

    let res_bytes = res.to_be_bytes();
    result.copy_from_slice(&res_bytes);

    return 0;
}
