use snarkvm_curves::bls12_377::{Fq, Fr, G1Affine};
use snarkvm_utilities::ToBytes;
use std::ops::{Add, Sub, Mul, Neg};
use snarkvm_fields::Field;
use snarkvm_fields::PrimeField;
use snarkvm_fields::SquareRootField;
use snarkvm_curves::AffineCurve;
use snarkvm_curves::ProjectiveCurve;

use std::slice;
use std::ptr;

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_privatetopublic(
            b_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a = G1Affine::prime_subgroup_generator();

    let b = unsafe { slice::from_raw_parts(b_bytes, 32) };
    let b = Fr::from_bytes_be_mod_order(b);

    let res = a.mul(b).to_affine();

    let res_x = match res.to_x_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    assert!(res_x.len() == 48);

    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let res_y = match res.to_y_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };

    assert!(res_y.len() == 48);
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_g1_add(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            b_x_bytes: *mut u8,
            b_y_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 48) };
    let a_x = Fq::from_bytes_be_mod_order(a_x);

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 48) };
    let a_y = Fq::from_bytes_be_mod_order(a_y);

    let a = G1Affine::new(a_x, a_y, false).to_projective();

    let b_x = unsafe { slice::from_raw_parts(b_x_bytes, 48) };
    let b_x = Fq::from_bytes_be_mod_order(b_x);

    let b_y = unsafe { slice::from_raw_parts(b_y_bytes, 48) };
    let b_y = Fq::from_bytes_be_mod_order(b_y);

    let b = G1Affine::new(b_x, b_y, false).to_projective();

    let res = a.add(b).to_affine();

    let res_x = match res.to_x_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    assert!(res_x.len() == 48);

    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let res_y = match res.to_y_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };

    assert!(res_y.len() == 48);
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_g1_mul(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            b_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 48) };
    let a_x = Fq::from_bytes_be_mod_order(a_x);

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 48) };
    let a_y = Fq::from_bytes_be_mod_order(a_y);

    let b = unsafe { slice::from_raw_parts(b_bytes, 32) };
    let b = Fr::from_bytes_be_mod_order(b);

    let a = G1Affine::new(a_x, a_y, false);

    let res = a.mul(b).to_affine();

    let res_x = match res.to_x_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    assert!(res_x.len() == 48);

    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let res_y = match res.to_y_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };

    assert!(res_y.len() == 48);
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_aleo_g1_neg(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 48) };
    let a_x = Fq::from_bytes_be_mod_order(a_x);

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 48) };
    let a_y = Fq::from_bytes_be_mod_order(a_y);

    let a = G1Affine::new(a_x, a_y, false).to_projective();

    let res = a.neg().to_affine();

    let res_x = match res.to_x_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    assert!(res_x.len() == 48);

    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let res_y = match res.to_y_coordinate().to_bytes_le() {
        Ok(v) => v,
        Err(_) => return -1,
    };

    assert!(res_y.len() == 48);
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

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
