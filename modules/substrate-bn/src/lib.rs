use std::slice;
use std::ptr;

use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

#[no_mangle]
pub extern "C" fn cryptofuzz_substrate_bn_g1_on_curve(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 32) };
    let a_x = match Fq::from_slice(a_x) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 32) };
    let a_y = match Fq::from_slice(a_y) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    match AffineG1::new(a_x, a_y) {
        Ok(_v) => return 0,
        Err(_e) => return -1,
    };
}

#[no_mangle]
pub extern "C" fn cryptofuzz_substrate_bn_g1_add(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            b_x_bytes: *mut u8,
            b_y_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 32) };
    let a_x = match Fq::from_slice(a_x) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 32) };
    let a_y = match Fq::from_slice(a_y) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a = match AffineG1::new(a_x, a_y) {
        Ok(v) => G1::from(v),
        Err(_e) => return -1,
    };

    let b_x = unsafe { slice::from_raw_parts(b_x_bytes, 32) };
    let b_x = match Fq::from_slice(b_x) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let b_y = unsafe { slice::from_raw_parts(b_y_bytes, 32) };
    let b_y = match Fq::from_slice(b_y) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let b = match AffineG1::new(b_x, b_y) {
        Ok(v) => G1::from(v),
        Err(_e) => return -1,
    };

    let res = match AffineG1::from_jacobian(a + b) {
        Some(v) => G1::from(v),
        None => return -1, /* XXX panic? */
    };

    let mut res_x: [u8; 32] = [0; 32];
    res.x().to_big_endian(&mut res_x).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let mut res_y: [u8; 32] = [0; 32];
    res.y().to_big_endian(&mut res_y).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_substrate_bn_g1_mul(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            b_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 32) };
    let a_x = match Fq::from_slice(a_x) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 32) };
    let a_y = match Fq::from_slice(a_y) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a = match AffineG1::new(a_x, a_y) {
        Ok(v) => G1::from(v),
        Err(_e) => return -1,
    };

    let b = unsafe { slice::from_raw_parts(b_bytes, 32) };
    let b = match Fr::from_slice(b) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let res = match AffineG1::from_jacobian(a * b) {
        Some(v) => G1::from(v),
        None => return -1, /* XXX panic? */
    };

    let mut res_x: [u8; 32] = [0; 32];
    res.x().to_big_endian(&mut res_x).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let mut res_y: [u8; 32] = [0; 32];
    res.y().to_big_endian(&mut res_y).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_substrate_bn_g1_neg(
            a_x_bytes: *mut u8,
            a_y_bytes: *mut u8,
            result_x: *mut u8,
            result_y: *mut u8) -> i32 {
    let a_x = unsafe { slice::from_raw_parts(a_x_bytes, 32) };
    let a_x = match Fq::from_slice(a_x) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a_y = unsafe { slice::from_raw_parts(a_y_bytes, 32) };
    let a_y = match Fq::from_slice(a_y) {
        Ok(v) => v,
        Err(_e) => return -1,
    };

    let a = match AffineG1::new(a_x, a_y) {
        Ok(v) => G1::from(v),
        Err(_e) => return -1,
    };

    let res = match AffineG1::from_jacobian(-a) {
        Some(v) => G1::from(v),
        None => return -1, /* XXX panic? */
    };

    let mut res_x: [u8; 32] = [0; 32];
    res.x().to_big_endian(&mut res_x).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_x.as_ptr(), result_x, res_x.len());
    }

    let mut res_y: [u8; 32] = [0; 32];
    res.y().to_big_endian(&mut res_y).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(res_y.as_ptr(), result_y, res_y.len());
    }

    return 0;
}
