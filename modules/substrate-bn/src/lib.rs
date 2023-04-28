use std::slice;
use std::ptr;

use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G1, G2, Gt, pairing_batch};
use std::convert::TryInto;

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
        None => {
            let r: [u8; 32] = [0; 32];
            unsafe {
                ptr::copy_nonoverlapping(r.as_ptr(), result_x, r.len());
                ptr::copy_nonoverlapping(r.as_ptr(), result_y, r.len());
            }
            return 0;
        },
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
        Err(_e) =>
            panic!("Cannot load Fr"),
    };

    let res = match AffineG1::from_jacobian(a * b) {
        Some(v) => G1::from(v),
        None => {
            assert!(b == Fr::zero());
            let r: [u8; 32] = [0; 32];
            unsafe {
                ptr::copy_nonoverlapping(r.as_ptr(), result_x, r.len());
                ptr::copy_nonoverlapping(r.as_ptr(), result_y, r.len());
            }
            return 0;
        },
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
        None => panic!("Point negation failed"),
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
pub extern "C" fn cryptofuzz_substrate_bn_batchverify(
            in_bytes: *mut u8,
            num_elements: u64) -> i32 {
    let mut i: isize  = 0;
    let mut groups = Vec::new();

    while i < (num_elements * 192).try_into().unwrap() {
        let g1_x = unsafe { slice::from_raw_parts(in_bytes.offset(0 + i), 32) };
        let g1_x = match Fq::from_slice(g1_x) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g1_y = unsafe { slice::from_raw_parts(in_bytes.offset(32 + i), 32) };
        let g1_y = match Fq::from_slice(g1_y) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g1 = match AffineG1::new(g1_x, g1_y) {
            Ok(v) => G1::from(v),
            Err(_e) => return -1,
        };

        let g2_v = unsafe { slice::from_raw_parts(in_bytes.offset(64 + i), 32) };
        let g2_v = match Fq::from_slice(g2_v) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g2_w = unsafe { slice::from_raw_parts(in_bytes.offset(96 + i), 32) };
        let g2_w = match Fq::from_slice(g2_w) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g2_vw = Fq2::new(g2_v, g2_w);

        let g2_x = unsafe { slice::from_raw_parts(in_bytes.offset(128 + i), 32) };
        let g2_x = match Fq::from_slice(g2_x) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g2_y = unsafe { slice::from_raw_parts(in_bytes.offset(160 + i), 32) };
        let g2_y = match Fq::from_slice(g2_y) {
            Ok(v) => v,
            Err(_e) => return -1,
        };

        let g2_xy = Fq2::new(g2_x, g2_y);

        let g2 = match AffineG2::new(g2_vw, g2_xy) {
            Ok(v) => G2::from(v),
            Err(_e) => return -1,
        };

        groups.push((g1, g2));
        i += 192;
    }

    let res = pairing_batch(&groups);

    if res == Gt::one() {
        return 1;
    } else {
        return 0;
    }
}
