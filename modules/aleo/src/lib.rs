use snarkvm_curves::bls12_377::{Fq, Fr};
use snarkvm_utilities::ToBytes;
use std::ops::{Add, Sub, Mul};
use snarkvm_fields::Field;
use snarkvm_fields::PrimeField;
use snarkvm_fields::SquareRootField;

use std::slice;
use std::ptr;

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_bignumcalc_fq(
            op: u64,
            bn0_bytes: *mut u8,
            bn1_bytes: *mut u8,
            result: *mut u8) -> i32 {
    let bn0 = unsafe { slice::from_raw_parts(bn0_bytes, 48) };
    let bn0 = Fq::from_bytes_be_mod_order(bn0);
    let bn1 = unsafe { slice::from_raw_parts(bn1_bytes, 48) };
    let bn1 = Fq::from_bytes_be_mod_order(bn1);
    let res: Fq;
    if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 2 {
        res = bn0.mul(bn1);
    } else if op == 3 {
        res = match bn0.inverse() {
            Some(v) => v,
            None => Fq::from(0u8),
        };
    } else if op == 4 {
        res = bn0.square();
    } else if op == 5 {
        res = match bn0.sqrt() {
            Some(v) => v.square(),
            None => Fq::from(0u8),
        };
    } else {
        return -1;
    }
    let r = match res.to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    unsafe {
        ptr::copy_nonoverlapping(r.as_ptr(), result, r.len());
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_bignumcalc_fr(
            op: u64,
            bn0_bytes: *mut u8,
            bn1_bytes: *mut u8,
            result: *mut u8) -> i32 {
    let bn0 = unsafe { slice::from_raw_parts(bn0_bytes, 32) };
    let bn0 = Fr::from_bytes_be_mod_order(bn0);
    let bn1 = unsafe { slice::from_raw_parts(bn1_bytes, 32) };
    let bn1 = Fr::from_bytes_be_mod_order(bn1);
    let res: Fr;
    if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 2 {
        res = bn0.mul(bn1);
    } else if op == 3 {
        res = match bn0.inverse() {
            Some(v) => v,
            None => Fr::from(0u8),
        };
    } else if op == 4 {
        res = bn0.square();
    } else if op == 5 {
        res = match bn0.sqrt() {
            Some(v) => v.square(),
            None => Fr::from(0u8),
        };
    } else {
        return -1;
    }
    let r = match res.to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    unsafe {
        ptr::copy_nonoverlapping(r.as_ptr(), result, r.len());
    }
    return 0;
}
