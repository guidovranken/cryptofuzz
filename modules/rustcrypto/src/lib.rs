use std::slice;
use std::ptr;

use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha1::{Sha1};
use streebog::{Streebog256, Streebog512};
use whirlpool::{Whirlpool};
use ripemd::{Ripemd160,Ripemd256,Ripemd320};
use sm3::{Sm3};
use gost94::{Gost94CryptoPro};
use md2::{Md2};
use md4::{Md4};
use md5::{Md5};
use groestl::{Groestl224, Groestl256, Groestl384, Groestl512};
use tiger::{Tiger};
use blake2::{Blake2b512, Blake2s256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512};
use fsb::{Fsb160, Fsb224, Fsb256, Fsb384, Fsb512};
use shabal::{Shabal256, Shabal512};
use k12::{KangarooTwelve, digest::{ExtendableOutput}};

use digest::{Digest,FixedOutput, KeyInit, Update};

use hkdf::Hkdf;

use hmac::{Mac, Hmac, HmacCore};
use hmac::digest::{
    block_buffer::Eager,
    core_api::{
        BlockSizeUser, BufferKindUser, CoreProxy,
        UpdateCore, FixedOutputCore, AlgorithmName, CoreWrapper
    },
    HashMarker,
};

use scrypt::{scrypt, Params as ScryptParams};

use crypto_bigint::{U256, Encoding, Integer, Zero};
use crypto_bigint::subtle::{ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess, ConditionallySelectable};
use crypto_bigint::{CheckedAdd, CheckedSub, CheckedMul};

use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
};

use cmac::{Cmac,Mac as cMac,NewMac};

use aes::{Aes128, Aes192, Aes256};
use cast5::Cast5;
use idea::Idea;
use blowfish::Blowfish;
use twofish::Twofish;
use threefish::Threefish512;
use serpent::Serpent;
use sm4::Sm4;
use des::Des;
use cipher::{
    BlockCipher, BlockEncrypt, StreamCipher,
    NewBlockCipher,
};
use ofb::Ofb;
use cfb_mode::Cfb;
use cfb8::Cfb8;
use cfb8::cipher::{AsyncStreamCipher};
use ofb::cipher::{NewCipher};

use std::convert::TryInto;
mod ids;
use crate::ids::{*};

use k256;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::signature::Signature;
use k256::ecdsa::signature::DigestVerifier;
use k256::elliptic_curve::sec1::FromEncodedPoint;

use p256;

use generic_array;

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

fn hash<D: Digest + digest::Reset >(
    parts: Vec<Vec<u8>>,
    resets: Vec<u8>,
    out: *mut u8) -> i32 {
    let mut hasher = D::new();

    let mut resetidx: usize = 0;
    let mut numresets: usize = 0;

    loop {
        let mut doreset: bool = false;
        for part in parts.iter() {
            if numresets < 5 && resetidx < resets.len() {
                doreset = (resets[resetidx] % 2) == 0;
                resetidx += 1;

                if doreset {
                    numresets += 1;
                    break;
                }
            }

            hasher.update(part);
        }
        if !doreset {
            break;
        }

        //hasher.reset();
        Digest::reset(&mut hasher);
    }

    let res = hasher.finalize();

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return res.len().try_into().unwrap();
}

fn k12(
    parts: Vec<Vec<u8>>,
    size: usize,
    out: *mut u8) -> i32 {
    let mut k12 = KangarooTwelve::new();

    for part in parts.iter() {
        k12.update(part);
    }

    let res = k12.finalize_boxed(size);

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return size as i32;
}

#[no_mangle]
pub extern "C" fn rustcrypto_hashes_hash(
    input_bytes: *const u8, input_size: libc::size_t,
    parts_bytes: *const libc::size_t, parts_size: libc::size_t,
    resets_bytes: *const u8, resets_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let resets = unsafe { slice::from_raw_parts(resets_bytes, resets_size) }.to_vec();

         if is_sha1(algorithm)            { return hash::<Sha1>(parts, resets, out); }
    else if is_sha224(algorithm)          { return hash::<Sha224>(parts, resets, out); }
    else if is_sha256(algorithm)          { return hash::<Sha256>(parts, resets, out); }
    else if is_sha384(algorithm)          { return hash::<Sha384>(parts, resets, out); }
    else if is_sha512(algorithm)          { return hash::<Sha512>(parts, resets, out); }
    else if is_streebog_256(algorithm)    { return hash::<Streebog256>(parts, resets, out); }
    else if is_streebog_512(algorithm)    { return hash::<Streebog512>(parts, resets, out); }
    else if is_whirlpool(algorithm)       { return hash::<Whirlpool>(parts, resets, out); }
    else if is_ripemd160(algorithm)       { return hash::<Ripemd160>(parts, resets, out); }
    else if is_ripemd256(algorithm)       { return hash::<Ripemd256>(parts, resets, out); }
    else if is_ripemd320(algorithm)       { return hash::<Ripemd320>(parts, resets, out); }
    else if is_gost_r_34_11_94(algorithm) { return hash::<Gost94CryptoPro>(parts, resets, out); }
    else if is_sm3(algorithm)             { return hash::<Sm3>(parts, resets, out); }
    else if is_md2(algorithm)             { return hash::<Md2>(parts, resets, out); }
    else if is_md4(algorithm)             { return hash::<Md4>(parts, resets, out); }
    else if is_md5(algorithm)             { return hash::<Md5>(parts, resets, out); }
    else if is_groestl_224(algorithm)     { return hash::<Groestl224>(parts, resets, out); }
    else if is_groestl_256(algorithm)     { return hash::<Groestl256>(parts, resets, out); }
    else if is_groestl_384(algorithm)     { return hash::<Groestl384>(parts, resets, out); }
    else if is_groestl_512(algorithm)     { return hash::<Groestl512>(parts, resets, out); }
    else if is_blake2b512(algorithm)      { return hash::<Blake2b512>(parts, resets, out); }
    else if is_blake2s256(algorithm)      { return hash::<Blake2s256>(parts, resets, out); }
    else if is_sha3_224(algorithm)        { return hash::<Sha3_224>(parts, resets, out); }
    else if is_sha3_256(algorithm)        { return hash::<Sha3_256>(parts, resets, out); }
    else if is_sha3_384(algorithm)        { return hash::<Sha3_384>(parts, resets, out); }
    else if is_sha3_512(algorithm)        { return hash::<Sha3_512>(parts, resets, out); }
    else if is_keccak_224(algorithm)      { return hash::<Keccak224>(parts, resets, out); }
    else if is_keccak_256(algorithm)      { return hash::<Keccak256>(parts, resets, out); }
    else if is_keccak_384(algorithm)      { return hash::<Keccak384>(parts, resets, out); }
    else if is_keccak_512(algorithm)      { return hash::<Keccak512>(parts, resets, out); }
    else if is_fsb_160(algorithm)         { return hash::<Fsb160>(parts, resets, out); }
    else if is_fsb_224(algorithm)         { return hash::<Fsb224>(parts, resets, out); }
    else if is_fsb_256(algorithm)         { return hash::<Fsb256>(parts, resets, out); }
    else if is_fsb_384(algorithm)         { return hash::<Fsb384>(parts, resets, out); }
    else if is_fsb_512(algorithm)         { return hash::<Fsb512>(parts, resets, out); }
    else if is_shabal_256(algorithm)      { return hash::<Shabal256>(parts, resets, out); }
    else if is_shabal_512(algorithm)      { return hash::<Shabal512>(parts, resets, out); }
    else if is_tiger(algorithm)           { return hash::<Tiger>(parts, resets, out); }
    else if is_k12_256(algorithm)         { return k12(parts, 32, out); }
    else if is_k12_512(algorithm)         { return k12(parts, 64, out); }
    else {
        return -1;
    }
}

fn hkdf<D: Clone + Default + FixedOutput + Update + digest::Reset + digest::core_api::CoreProxy>(
    password: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    keysize: u64,
    out: *mut u8) -> i32
    where D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: digest::generic_array::typenum::IsLess<digest::generic_array::typenum::U256>,
    digest::generic_array::typenum::Le<<D::Core as BlockSizeUser>::BlockSize, digest::generic_array::typenum::U256>: digest::generic_array::typenum::NonZero {
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
    /* TODO */
    /*
    else if is_blake2b512(algorithm)      { return hkdf::<Blake2b512>(password, salt, info, keysize, out); }
    else if is_blake2s256(algorithm)      { return hkdf::<Blake2s256>(password, salt, info, keysize, out); }
    */
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

/*
fn hmac<D: BlockInput + Clone + Default + FixedOutput + Update + Reset>(
    parts: Vec<Vec<u8>>,
    resets: Vec<u8>,
    key: Vec<u8>,
    out: *mut u8) -> i32 {

    let mut hmac = match Hmac::<D>::new_from_slice(&key) {
        Ok(_v) => _v,
        Err(_e) => return -1,
    };

    let mut resetidx: usize = 0;
    let mut numresets: usize = 0;

    loop {
        let mut doreset: bool = false;
        for part in parts.iter() {
            if numresets < 5 && resetidx < resets.len() {
                doreset = (resets[resetidx] % 2) == 0;
                resetidx += 1;

                if doreset {
                    numresets += 1;
                    break;
                }
            }

            hmac.update(part);
        }
        if !doreset {
            break;
        }

        hmac.reset();
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
    resets_bytes: *const u8, resets_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let key = unsafe { slice::from_raw_parts(key_bytes, key_size) }.to_vec();
    let resets = unsafe { slice::from_raw_parts(resets_bytes, resets_size) }.to_vec();

         if is_sha1(algorithm)            { return hmac::<Sha1>(parts, resets, key, out); }
    else if is_sha224(algorithm)          { return hmac::<Sha224>(parts, resets, key, out); }
    else if is_sha256(algorithm)          { return hmac::<Sha256>(parts, resets, key, out); }
    else if is_sha384(algorithm)          { return hmac::<Sha384>(parts, resets, key, out); }
    else if is_sha512(algorithm)          { return hmac::<Sha512>(parts, resets, key, out); }
    else if is_streebog_256(algorithm)    { return hmac::<Streebog256>(parts, resets, key, out); }
    else if is_streebog_512(algorithm)    { return hmac::<Streebog512>(parts, resets, key, out); }
    else if is_whirlpool(algorithm)       { return hmac::<Whirlpool>(parts, resets, key, out); }
    else if is_ripemd160(algorithm)       { return hmac::<Ripemd160>(parts, resets, key, out); }
    else if is_ripemd256(algorithm)       { return hmac::<Ripemd256>(parts, resets, key, out); }
    else if is_ripemd320(algorithm)       { return hmac::<Ripemd320>(parts, resets, key, out); }
    else if is_gost_r_34_11_94(algorithm) { return hmac::<Gost94CryptoPro>(parts, resets, key, out); }
    else if is_sm3(algorithm)             { return hmac::<Sm3>(parts, resets, key, out); }
    else if is_md2(algorithm)             { return hmac::<Md2>(parts, resets, key, out); }
    else if is_md4(algorithm)             { return hmac::<Md4>(parts, resets, key, out); }
    else if is_md5(algorithm)             { return hmac::<Md5>(parts, resets, key, out); }
    else if is_groestl_224(algorithm)     { return hmac::<Groestl224>(parts, resets, key, out); }
    else if is_groestl_256(algorithm)     { return hmac::<Groestl256>(parts, resets, key, out); }
    else if is_groestl_384(algorithm)     { return hmac::<Groestl384>(parts, resets, key, out); }
    else if is_groestl_512(algorithm)     { return hmac::<Groestl512>(parts, resets, key, out); }
    else if is_blake2b512(algorithm)      { return hmac::<Blake2b>(parts, resets, key, out); }
    else if is_blake2s256(algorithm)      { return hmac::<Blake2s>(parts, resets, key, out); }
    else if is_sha3_224(algorithm)        { return hmac::<Sha3_224>(parts, resets, key, out); }
    else if is_sha3_256(algorithm)        { return hmac::<Sha3_256>(parts, resets, key, out); }
    else if is_sha3_384(algorithm)        { return hmac::<Sha3_384>(parts, resets, key, out); }
    else if is_sha3_512(algorithm)        { return hmac::<Sha3_512>(parts, resets, key, out); }
    else if is_keccak_224(algorithm)      { return hmac::<Keccak224>(parts, resets, key, out); }
    else if is_keccak_256(algorithm)      { return hmac::<Keccak256>(parts, resets, key, out); }
    else if is_keccak_384(algorithm)      { return hmac::<Keccak384>(parts, resets, key, out); }
    else if is_keccak_512(algorithm)      { return hmac::<Keccak512>(parts, resets, key, out); }
    else if is_fsb_160(algorithm)         { return hmac::<Fsb160>(parts, resets, key, out); }
    else if is_fsb_224(algorithm)         { return hmac::<Fsb224>(parts, resets, key, out); }
    else if is_fsb_256(algorithm)         { return hmac::<Fsb256>(parts, resets, key, out); }
    else if is_fsb_384(algorithm)         { return hmac::<Fsb384>(parts, resets, key, out); }
    else if is_fsb_512(algorithm)         { return hmac::<Fsb512>(parts, resets, key, out); }
    else if is_shabal_256(algorithm)      { return hmac::<Shabal256>(parts, resets, key, out); }
    else if is_shabal_512(algorithm)      { return hmac::<Shabal512>(parts, resets, key, out); }
    else if is_tiger(algorithm)           { return hmac::<Tiger>(parts, resets, key, out); }
    else {
        return -1;
    }
}
*/

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

fn pbkdf2_<D: Mac + Sync + KeyInit + Update + FixedOutput + Clone>(
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
    /* TODO */
    //else if is_blake2b512(algorithm)      { return pbkdf2_::<Hmac<Blake2b512>>(password, salt, iterations, keysize, out); }
    //else if is_blake2s256(algorithm)      { return pbkdf2_::<Hmac<Blake2s256>>(password, salt, iterations, keysize, out); }
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
    resets_bytes: *const u8, resets_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    out: *mut u8) -> i32 {
    let parts = create_parts(input_bytes, input_size, parts_bytes, parts_size);
    let key = unsafe { slice::from_raw_parts(key_bytes, key_size) }.to_vec();
    let resets = unsafe { slice::from_raw_parts(resets_bytes, resets_size) }.to_vec();

    let mut mac = match Cmac::<Aes128>::new_from_slice(&key) {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    let mut resetidx: usize = 0;
    let mut numresets: usize = 0;

    loop {
        let mut doreset: bool = false;
        for part in parts.iter() {
            if numresets < 5 && resetidx < resets.len() {
                doreset = (resets[resetidx] % 2) == 0;
                resetidx += 1;

                if doreset {
                    numresets += 1;
                    break;
                }
            }

            mac.update(part);
        }
        if !doreset {
            break;
        }

        mac.reset();
    }

    let res = mac.finalize().into_bytes();

    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), out, res.len());
    }

    return res.len() as i32;
}

fn cfb_crypt<C: BlockCipher + BlockEncrypt + NewBlockCipher>(
    mut input: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    encrypt: bool,
    out: *mut u8) -> i32 {
    let mut cipher = match Cfb::<C>::new_from_slices(&key, &iv) {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    if encrypt {
        cipher.encrypt(&mut input);
    } else {
        cipher.decrypt(&mut input);
    }

    unsafe {
        ptr::copy_nonoverlapping(input.as_ptr(), out, input.len());
    }

    return input.len() as i32;
}

fn cfb8_crypt<C: BlockCipher + BlockEncrypt + NewBlockCipher>(
    mut input: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    encrypt: bool,
    out: *mut u8) -> i32 {
    let mut cipher = match Cfb8::<C>::new_from_slices(&key, &iv) {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    if encrypt {
        cipher.encrypt(&mut input);
    } else {
        cipher.decrypt(&mut input);
    }

    unsafe {
        ptr::copy_nonoverlapping(input.as_ptr(), out, input.len());
    }

    return input.len() as i32;
}

fn ofb_crypt<C: BlockCipher + BlockEncrypt + NewBlockCipher>(
    mut input: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    _encrypt: bool,
    out: *mut u8) -> i32 {
    let mut cipher = match Ofb::<C>::new_from_slices(&key, &iv) {
        Ok(v) => (v),
        Err(_e) => return -1,
    };

    cipher.apply_keystream(&mut input);

    unsafe {
        ptr::copy_nonoverlapping(input.as_ptr(), out, input.len());
    }

    return input.len() as i32;
}

fn crypt(
    input_bytes: *const u8, input_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    iv_bytes: *const u8, iv_size: libc::size_t,
    algorithm: u64,
    encrypt: bool,
    out: *mut u8) -> i32 {

    let input = unsafe { slice::from_raw_parts(input_bytes, input_size) }.to_vec();
    let key = unsafe { slice::from_raw_parts(key_bytes, key_size) }.to_vec();
    let iv = unsafe { slice::from_raw_parts(iv_bytes, iv_size) }.to_vec();

    if is_cipher_aes_128_ofb(algorithm) {
        return ofb_crypt::<Aes128>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_192_ofb(algorithm) {
        return ofb_crypt::<Aes192>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_256_ofb(algorithm) {
        return ofb_crypt::<Aes256>(input, key, iv, encrypt, out);
    } else if is_cipher_cast5_ofb(algorithm) {
        return ofb_crypt::<Cast5>(input, key, iv, encrypt, out);
    } else if is_cipher_idea_ofb(algorithm) {
        return ofb_crypt::<Idea>(input, key, iv, encrypt, out);
    } else if is_cipher_blowfish_ofb(algorithm) {
        return ofb_crypt::<Blowfish>(input, key, iv, encrypt, out);
    } else if is_cipher_twofish_ofb(algorithm) {
        return ofb_crypt::<Twofish>(input, key, iv, encrypt, out);
    } else if is_cipher_threefish_512_ofb(algorithm) {
        return ofb_crypt::<Threefish512>(input, key, iv, encrypt, out);
    } else if is_cipher_serpent_ofb(algorithm) {
        return ofb_crypt::<Serpent>(input, key, iv, encrypt, out);
    } else if is_cipher_sm4_ofb(algorithm) {
        return ofb_crypt::<Sm4>(input, key, iv, encrypt, out);
    } else if is_cipher_des_ofb(algorithm) {
        return ofb_crypt::<Des>(input, key, iv, encrypt, out);

    } else if is_cipher_aes_128_cfb(algorithm) {
        return cfb_crypt::<Aes128>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_192_cfb(algorithm) {
        return cfb_crypt::<Aes192>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_256_cfb(algorithm) {
        return cfb_crypt::<Aes256>(input, key, iv, encrypt, out);
    } else if is_cipher_cast5_cfb(algorithm) {
        return cfb_crypt::<Cast5>(input, key, iv, encrypt, out);
    } else if is_cipher_idea_cfb(algorithm) {
        return cfb_crypt::<Idea>(input, key, iv, encrypt, out);
    } else if is_cipher_blowfish_cfb(algorithm) {
        return cfb_crypt::<Blowfish>(input, key, iv, encrypt, out);
    } else if is_cipher_twofish_cfb(algorithm) {
        return cfb_crypt::<Twofish>(input, key, iv, encrypt, out);
    } else if is_cipher_threefish_512_cfb(algorithm) {
        return cfb_crypt::<Threefish512>(input, key, iv, encrypt, out);
    } else if is_cipher_serpent_cfb(algorithm) {
        return cfb_crypt::<Serpent>(input, key, iv, encrypt, out);
    } else if is_cipher_sm4_cfb(algorithm) {
        return cfb_crypt::<Sm4>(input, key, iv, encrypt, out);
    } else if is_cipher_des_cfb(algorithm) {
        return cfb_crypt::<Des>(input, key, iv, encrypt, out);

    } else if is_cipher_aes_128_cfb8(algorithm) {
        return cfb8_crypt::<Aes128>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_192_cfb8(algorithm) {
        return cfb8_crypt::<Aes192>(input, key, iv, encrypt, out);
    } else if is_cipher_aes_256_cfb8(algorithm) {
        return cfb8_crypt::<Aes256>(input, key, iv, encrypt, out);
    } else if is_cipher_des_cfb8(algorithm) {
        return cfb8_crypt::<Des>(input, key, iv, encrypt, out);

    } else {
        return -1;
    }
}

#[no_mangle]
pub extern "C" fn rustcrypto_symmetric_encrypt(
    input_bytes: *const u8, input_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    iv_bytes: *const u8, iv_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {

    return crypt(
        input_bytes, input_size,
        key_bytes, key_size,
        iv_bytes, iv_size,
        algorithm,
        true,
        out);
}

#[no_mangle]
pub extern "C" fn rustcrypto_symmetric_decrypt(
    input_bytes: *const u8, input_size: libc::size_t,
    key_bytes: *const u8, key_size: libc::size_t,
    iv_bytes: *const u8, iv_size: libc::size_t,
    algorithm: u64,
    out: *mut u8) -> i32 {

    return crypt(
        input_bytes, input_size,
        key_bytes, key_size,
        iv_bytes, iv_size,
        algorithm,
        false,
        out);
}

#[no_mangle]
pub extern "C" fn rustcrypto_bigint_bignumcalc(
            op: u64,
            bn0: &[u8; 32],
            bn1: &[u8; 32],
            bn2: &[u8; 32],
            modifier: u8,
            result: &mut [u8; 32]) -> i32 {
    let bn0 = U256::from_be_bytes(*bn0);
    let bn1 = U256::from_be_bytes(*bn1);
    let bn2 = U256::from_be_bytes(*bn2);

    let res: U256;
    if is_add(op) {
        match modifier % 2 {
            0 => res = bn0.wrapping_add(&bn1),
            1 => {
                let r = bn0.checked_add(&bn1);
                if bool::from(r.is_none()) {
                    return -1;
                }
                res = r.unwrap();
            },
            _ => panic!(),
        }
    } else if is_sub(op) {
        match modifier % 2 {
            0 => res = bn0.wrapping_sub(&bn1),
            1 => {
                let r = bn0.checked_sub(&bn1);
                if bool::from(r.is_none()) {
                    return -1;
                }
                res = r.unwrap();
            },
            _ => panic!(),
        }
    } else if is_mul(op) {
        match modifier % 2 {
            0 => res = bn0.wrapping_mul(&bn1),
            1 => {
                let r = bn0.checked_mul(&bn1);
                if bool::from(r.is_none()) {
                    return -1;
                }
                res = r.unwrap();
            },
            _ => panic!(),
        }
    } else if is_div(op) {
        if bool::from(bn1.is_zero()) {
            return -1;
        }
        res = bn0.wrapping_div(&bn1);
    } else if is_mod(op) {
        if bool::from(bn1.is_zero()) {
            return -1;
        }
        if bn0 < bn1 {
            return -1;
        }
        res = bn0.wrapping_rem(&bn1);
    } else if is_addmod(op) {
        /* Docs: "Assumes self and rhs are < p." */
        if bn0 >= bn2 || bn1 >= bn2 {
            return -1;
        }
        res = bn0.add_mod(&bn1, &bn2);
    } else if is_submod(op) {
        /* Docs: "Assumes self and rhs are < p." */
        if bn0 >= bn2 || bn1 >= bn2 {
            return -1;
        }
        res = bn0.sub_mod(&bn1, &bn2);
    } else if is_and(op) {
        match modifier % 3 {
            0 => res = bn0.bitand(&bn1),
            1 => res = bn0.wrapping_and(&bn1),
            2 => res = bn0.checked_and(&bn1).unwrap(),
            _ => panic!(),
        }
    } else if is_or(op) {
        match modifier % 3 {
            0 => res = bn0.bitor(&bn1),
            1 => res = bn0.wrapping_or(&bn1),
            2 => res = bn0.checked_or(&bn1).unwrap(),
            _ => panic!(),
        }
    } else if is_xor(op) {
        match modifier % 3 {
            0 => res = bn0.bitxor(&bn1),
            1 => res = bn0.wrapping_xor(&bn1),
            2 => res = bn0.checked_xor(&bn1).unwrap(),
            _ => panic!(),
        }
    } else if is_not(op) {
        let bn0_ = bn0.wrapping_sub(&U256::ONE);
        res = bn0_.not();
    } else if is_iseq(op) {
        res = match modifier % 3 {
            0 => if bn0 == bn1 { U256::ONE } else { U256::ZERO },
            1 => if bn0.eq(&bn1) { U256::ONE } else { U256::ZERO },
            2 => if bool::from(bn0.ct_eq(&bn1)) { U256::ONE } else { U256::ZERO },
            _ => panic!(),
        };
    } else if is_isgt(op) {
        res = match modifier % 3 {
            0 => if bn0 > bn1 { U256::ONE } else { U256::ZERO },
            1 => if bn0.gt(&bn1) { U256::ONE } else { U256::ZERO },
            2 => if bool::from(bn0.ct_gt(&bn1)) { U256::ONE } else { U256::ZERO },
            _ => panic!(),
        };
    } else if is_isgte(op) {
        res = if bn0 >= bn1 { U256::ONE } else { U256::ZERO };
    } else if is_islt(op) {
        res = match modifier % 3 {
            0 => if bn0 < bn1 { U256::ONE } else { U256::ZERO },
            1 => if bn0.lt(&bn1) { U256::ONE } else { U256::ZERO },
            2 => if bool::from(bn0.ct_lt(&bn1)) { U256::ONE } else { U256::ZERO },
            _ => panic!(),
        };
    } else if is_islte(op) {
        res = if bn0 <= bn1 { U256::ONE } else { U256::ZERO };
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
    } else if is_lshift1(op) {
        res = bn0 << 1;
    } else if is_one(op) {
        res = U256::ONE;
    } else if is_condset(op) {
        let mut r = U256::ZERO;
        r.conditional_assign(&bn0, !bn1.is_zero());
        res = r;
    } else if is_set(op) {
        res = match modifier % 2 {
            0 => bn0,
            1 => U256::new(*bn0.limbs()),
            2 => U256::from_uint_array(bn0.to_uint_array()),
            _ => panic!(),
        };
    } else {
        return -1;
    }

    let res_bytes = res.to_be_bytes();
    result.copy_from_slice(&res_bytes);

    return 0;
}

#[no_mangle]
pub extern "C" fn rustcrypto_ecc_privatetopublic(curve: u64, sk_bytes: &[u8; 32], pk_bytes: &mut [u8; 65]) -> i32 {
    if is_secp256k1(curve) {
        let sk = match k256::SecretKey::from_be_bytes(sk_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        let pk = sk.public_key();
        let pk_point = pk.to_encoded_point(false);
        let pk_bin = pk_point.to_bytes();
        pk_bytes.copy_from_slice(&pk_bin);
        return 0;
    } else if is_secp256r1(curve) {
        let sk = match p256::SecretKey::from_be_bytes(sk_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        let pk = sk.public_key();
        let pk_point = pk.to_encoded_point(false);
        let pk_bin = pk_point.to_bytes();
        pk_bytes.copy_from_slice(&pk_bin);
        return 0;
    }

    panic!("Invalid curve");
}

#[no_mangle]
pub extern "C" fn rustcrypto_validate_pubkey(curve: u64, pk_bytes: &[u8; 65]) -> i32 {
    if is_secp256k1(curve) {
        return match k256::PublicKey::from_sec1_bytes(pk_bytes) {
            Ok(_v) => 0,
            Err(_e) => -1,
        };
    } else if is_secp256r1(curve) {
        return match p256::PublicKey::from_sec1_bytes(pk_bytes) {
            Ok(_v) => 0,
            Err(_e) => -1,
        };
    }

    panic!("Invalid curve");
}

#[no_mangle]
pub extern "C" fn rustcrypto_ecdsa_sign(curve: u64, msg_bytes: &[u8; 32], sk_bytes: &[u8; 32], sig_bytes: &mut [u8; 64]) -> i32 {
    if is_secp256k1(curve) {
        let sk = match k256::ecdsa::SigningKey::from_bytes(sk_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        let sig: k256::ecdsa::Signature = sk.sign(msg_bytes);
        sig_bytes.copy_from_slice(&sig.as_bytes());
        return 0;
    } else if is_secp256r1(curve) {
        let sk = match p256::ecdsa::SigningKey::from_bytes(sk_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        let sig: p256::ecdsa::Signature = sk.sign(msg_bytes);
        sig_bytes.copy_from_slice(&sig.as_bytes());
        return 0;
    }

    panic!("Invalid curve");
}

#[no_mangle]
pub extern "C" fn rustcrypto_ecc_point_add(curve: u64, a_bytes: &[u8; 65], b_bytes: &[u8; 65], res_bytes: &mut [u8; 65]) -> i32 {
    if is_secp256k1(curve) {
        let a = match k256::EncodedPoint::from_bytes(a_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let a_affine = k256::AffinePoint::from_encoded_point(&a);
        if bool::from(a_affine.is_none()) {
            return -1;
        }

        let a_projective: k256::ProjectivePoint = a_affine.unwrap().into();

        let b = match k256::EncodedPoint::from_bytes(b_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let b_affine = k256::AffinePoint::from_encoded_point(&b);
        if bool::from(b_affine.is_none()) {
            return -1;
        }

        let b_projective: k256::ProjectivePoint = b_affine.unwrap().into();

        let res_projective = a_projective + b_projective;
        let res_affine = res_projective.to_affine();

        let res = res_affine.to_encoded_point(false);
        if res.len() != 65 {
            return -1;
        }
        res_bytes.copy_from_slice(&res.as_bytes());

        return 0;
    } else if is_secp256r1(curve) {
        let a = match p256::EncodedPoint::from_bytes(a_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let a_affine = p256::AffinePoint::from_encoded_point(&a);
        if bool::from(a_affine.is_none()) {
            return -1;
        }

        let a_projective: p256::ProjectivePoint = a_affine.unwrap().into();

        let b = match p256::EncodedPoint::from_bytes(b_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let b_affine = p256::AffinePoint::from_encoded_point(&b);
        if bool::from(b_affine.is_none()) {
            return -1;
        }

        let b_projective: p256::ProjectivePoint = b_affine.unwrap().into();

        let res_projective = a_projective + b_projective;
        let res_affine = res_projective.to_affine();

        let res = res_affine.to_encoded_point(false);
        if res.len() != 65 {
            return -1;
        }
        res_bytes.copy_from_slice(&res.as_bytes());

        return 0;
    }

    panic!("Invalid curve");
}

#[no_mangle]
pub extern "C" fn rustcrypto_ecc_point_mul(curve: u64, a_bytes: &[u8; 65], b_bytes: &[u8; 32], res_bytes: &mut [u8; 65]) -> i32 {
    if is_secp256k1(curve) {
        let a = match k256::EncodedPoint::from_bytes(a_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let a_affine = k256::AffinePoint::from_encoded_point(&a);
        if bool::from(a_affine.is_none()) {
            return -1;
        }

        let a_projective: k256::ProjectivePoint = a_affine.unwrap().into();

        let b = <k256::Scalar as k256::elliptic_curve::ops::Reduce::<elliptic_curve::bigint::U256>>::from_be_bytes_reduced(generic_array::GenericArray::<u8, generic_array::typenum::U32>::clone_from_slice(b_bytes));
        let res_projective = a_projective * b;
        let res_affine = res_projective.to_affine();

        let res = res_affine.to_encoded_point(false);
        if res.len() != 65 {
            return -1;
        }
        res_bytes.copy_from_slice(&res.as_bytes());

        return 0;
    } else if is_secp256r1(curve) {
        let a = match p256::EncodedPoint::from_bytes(a_bytes) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };

        let a_affine = p256::AffinePoint::from_encoded_point(&a);
        if bool::from(a_affine.is_none()) {
            return -1;
        }

        let a_projective: p256::ProjectivePoint = a_affine.unwrap().into();

        let b = <p256::Scalar as p256::elliptic_curve::ops::Reduce::<elliptic_curve::bigint::U256>>::from_be_bytes_reduced(generic_array::GenericArray::<u8, generic_array::typenum::U32>::clone_from_slice(b_bytes));
        let res_projective = a_projective * b;
        let res_affine = res_projective.to_affine();

        let res = res_affine.to_encoded_point(false);
        if res.len() != 65 {
            return -1;
        }
        res_bytes.copy_from_slice(&res.as_bytes());

        return 0;
    }


    panic!("Invalid curve");
}
