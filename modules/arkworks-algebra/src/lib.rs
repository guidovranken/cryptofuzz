use std::slice;
use std::ptr;
use std::convert::TryInto;
use std::convert::TryFrom;

use ark_ff::biginteger::BigInteger256;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::Field;
use ark_ff::SquareRootField;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;

use std::ops::Add;
use std::ops::Neg;

use ark_bn254;
use ark_bls12_381;

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = BigInteger256::new(arr);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = BigInteger256::new(arr);

    let mut res = BigInteger256::new([0u64; 4]);

    if /*op == 0 {
        res = bn0;
        res.add_with_carry(&bn1);
    } else if op == 1 {
        res = bn0;
        res.sub_with_borrow(&bn1);
    } else if */ op == 2 {
        res = bn0;
        res.mul2();
    } else if op == 3 {
        if bn1.num_bits() == 0 {
            return -1;
        }
        if bn1.num_bits() > 8 {
            return -1;
        }
        res = bn0;
        res.muln(bn1.as_ref()[0] as u32);
    } else if op == 4 {
        if bn1.num_bits() == 0 {
            return -1;
        }
        if bn1.num_bits() > 8 {
            return -1;
        }
        res = bn0;
        res.divn(bn1.as_ref()[0] as u32);
    } else {
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(res.as_ref().as_ptr(), result, 4);
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc_bn254_fq(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bn254::Fq::new(BigInteger256::new([0u64; 4]));

    if op == 5 {
        res = match bn0.inverse() {
            Some(v) => v,
            None => 0.into(),
        };
    } else if op == 6 {
        res = bn0.square();
    } else if op == 7 {
        res = match bn0.sqrt() {
            Some(v) => v.square(),
            None => 0.into(),
        };
    } else {
        return -1;
    }

    let res_bn : BigInteger256 = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bn.as_ref().as_ptr(), result, 4);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc_bn254_fr(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = match ark_bn254::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = match ark_bn254::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bn254::Fr::new(BigInteger256::new([0u64; 4]));

    if op == 5 {
        res = match bn0.inverse() {
            Some(v) => v,
            None => 0.into(),
        };
    } else if op == 6 {
        res = bn0.square();
    } else if op == 7 {
        res = match bn0.sqrt() {
            Some(v) => v.square(),
            None => 0.into(),
        };
    } else {
        return -1;
    }

    let res_bn : BigInteger256 = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bn.as_ref().as_ptr(), result, 4);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc_bls12_381_fr(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = match ark_bls12_381::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = match ark_bls12_381::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bls12_381::Fr::new(BigInteger256::new([0u64; 4]));

    if op == 5 {
        res = match bn0.inverse() {
            Some(v) => v,
            None => 0.into(),
        };
    } else if op == 6 {
        res = bn0.square();
    } else if op == 7 {
        res = match bn0.sqrt() {
            Some(v) => v.square(),
            None => 0.into(),
        };
    } else {
        return -1;
    }
    let res_bn : BigInteger256 = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bn.as_ref().as_ptr(), result, 4);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_add_bn254(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            bx_bytes: *mut u64,
            by_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 4)});
    let ax = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 4)});
    let ay = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bn254::G1Affine::new(ax, ay, false);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bx_bytes, 4)});
    let bx = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(by_bytes, 4)});
    let by = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let b = ark_bn254::G1Affine::new(bx, by, false);


    let res = a.add(b);

    if !a.is_on_curve() {
        return -1;
    }

    if !b.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger256 = res.x.into();
    let res_bn_y : BigInteger256 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 4);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 4);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_mul_bn254(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            b_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 4)});
    let ax = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 4)});
    let ay = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bn254::G1Affine::new(ax, ay, false);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(b_bytes, 4)});
    let b = match ark_bn254::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let res = g1.mul(b).into_affine();

    if !g1.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger256 = res.x.into();
    let res_bn_y : BigInteger256 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 4);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 4);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_neg_bn254(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 4)});
    let ax = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 4)});
    let ay = match ark_bn254::Fq::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bn254::G1Affine::new(ax, ay, false);

    let res = g1.neg();

    if !g1.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger256 = res.x.into();
    let res_bn_y : BigInteger256 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 4);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 4);
    }

    return 0;
}
