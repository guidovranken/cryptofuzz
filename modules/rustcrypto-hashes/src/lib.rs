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

         if is_SHA1(algorithm)            { return hash::<Sha1>(parts, out); }
    else if is_SHA224(algorithm)          { return hash::<Sha224>(parts, out); }
    else if is_SHA256(algorithm)          { return hash::<Sha256>(parts, out); }
    else if is_SHA384(algorithm)          { return hash::<Sha384>(parts, out); }
    else if is_SHA512(algorithm)          { return hash::<Sha512>(parts, out); }
    else if is_STREEBOG_256(algorithm)    { return hash::<Streebog256>(parts, out); }
    else if is_STREEBOG_512(algorithm)    { return hash::<Streebog512>(parts, out); }
    else if is_WHIRLPOOL(algorithm)       { return hash::<Whirlpool>(parts, out); }
    else if is_RIPEMD160(algorithm)       { return hash::<Ripemd160>(parts, out); }
    else if is_RIPEMD256(algorithm)       { return hash::<Ripemd256>(parts, out); }
    else if is_RIPEMD320(algorithm)       { return hash::<Ripemd320>(parts, out); }
    else if is_GOST_R_34_11_94(algorithm) { return hash::<Gost94CryptoPro>(parts, out); }
    else if is_SM3(algorithm)             { return hash::<Sm3>(parts, out); }
    else if is_MD2(algorithm)             { return hash::<Md2>(parts, out); }
    else if is_MD4(algorithm)             { return hash::<Md4>(parts, out); }
    else if is_MD5(algorithm)             { return hash::<Md5>(parts, out); }
    else if is_GROESTL_224(algorithm)     { return hash::<Groestl224>(parts, out); }
    else if is_GROESTL_256(algorithm)     { return hash::<Groestl256>(parts, out); }
    else if is_GROESTL_384(algorithm)     { return hash::<Groestl384>(parts, out); }
    else if is_GROESTL_512(algorithm)     { return hash::<Groestl512>(parts, out); }
    else if is_BLAKE2B512(algorithm)      { return hash::<Blake2b>(parts, out); }
    else if is_BLAKE2S256(algorithm)      { return hash::<Blake2s>(parts, out); }
    else if is_SHA3_224(algorithm)        { return hash::<Sha3_224>(parts, out); }
    else if is_SHA3_256(algorithm)        { return hash::<Sha3_256>(parts, out); }
    else if is_SHA3_384(algorithm)        { return hash::<Sha3_384>(parts, out); }
    else if is_SHA3_512(algorithm)        { return hash::<Sha3_512>(parts, out); }
    else if is_KECCAK_224(algorithm)      { return hash::<Keccak224>(parts, out); }
    else if is_KECCAK_256(algorithm)      { return hash::<Keccak256>(parts, out); }
    else if is_KECCAK_384(algorithm)      { return hash::<Keccak384>(parts, out); }
    else if is_KECCAK_512(algorithm)      { return hash::<Keccak512>(parts, out); }
    else if is_FSB_160(algorithm)         { return hash::<Fsb160>(parts, out); }
    else if is_FSB_224(algorithm)         { return hash::<Fsb224>(parts, out); }
    else if is_FSB_256(algorithm)         { return hash::<Fsb256>(parts, out); }
    else if is_FSB_384(algorithm)         { return hash::<Fsb384>(parts, out); }
    else if is_FSB_512(algorithm)         { return hash::<Fsb512>(parts, out); }
    else if is_SHABAL_256(algorithm)      { return hash::<Shabal256>(parts, out); }
    else if is_SHABAL_512(algorithm)      { return hash::<Shabal512>(parts, out); }
    else {
        return -1;
    }
}
