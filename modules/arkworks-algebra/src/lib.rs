use std::slice;
use std::ptr;
use std::convert::TryInto;
use std::convert::TryFrom;

use ark_ff::biginteger::BigInteger256;
use ark_ff::biginteger::BigInteger384;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::Field;
use ark_ff::SquareRootField;
use ark_ec::AffineCurve;
use ark_ec::ProjectiveCurve;

use std::ops::{Add, Sub, Mul, Neg};

use ark_bn254;
use ark_bls12_381;
use ark_bls12_377;

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

    if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 5 {
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
    } else if op == 8 {
        res = bn0.mul(bn1);
    } else if op == 9 {
        res = bn0.neg();
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
pub extern "C" fn arkworks_algebra_bignumcalc_bls12_381_fq(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 6)});
    let bn0 = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 6)});
    let bn1 = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bls12_381::Fq::new(BigInteger384::new([0u64; 6]));

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
    } else if op == 8 {
        res = bn0.mul(bn1);
    } else if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 9 {
        res = bn0.neg();
    } else {
        return -1;
    }

    let res_bn : BigInteger384 = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bn.as_ref().as_ptr(), result, 6);
    }

    return 0;
}

/* BN254 */

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_isoncurve_bn254(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64) -> i32 {
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

    if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_privatetopublic_bn254(
            priv_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    let g1 = ark_bn254::G1Affine::prime_subgroup_generator();

    arr.clone_from_slice(unsafe{slice::from_raw_parts(priv_bytes, 4)});
    let privv = match ark_bn254::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let res = g1.mul(privv).into_affine();

    let res_bn_x : BigInteger256 = res.x.into();
    let res_bn_y : BigInteger256 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 4);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 4);
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

    if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
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

/* BLS 12-381 */

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_isoncurve_bls12_381(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_381::G1Affine::new(ax, ay, false);

    if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_privatetopublic_bls12_381(
            priv_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    let g1 = ark_bls12_381::G1Affine::prime_subgroup_generator();

    arr.clone_from_slice(unsafe{slice::from_raw_parts(priv_bytes, 4)});
    let privv = match ark_bls12_381::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let res = g1.mul(privv).into_affine();

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}


#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_add_bls12_381(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            bx_bytes: *mut u64,
            by_bytes: *mut u64,
            affine: i32,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_381::G1Affine::new(ax, ay, false);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bx_bytes, 6)});
    let bx = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(by_bytes, 6)});
    let by = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let b = ark_bls12_381::G1Affine::new(bx, by, false);

    let res = match affine {
        1 => a.add(b),
        0 => a.into_projective().add(b.into_projective()).into_affine(),
        _ => { panic!("Invalid"); }
    };

    if !a.is_on_curve() {
        return -1;
    }

    if !b.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_mul_bls12_381(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            b_bytes: *mut u64,
            affine: i32,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];
    let mut arr4: [u64; 4] = [0; 4];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bls12_381::G1Affine::new(ax, ay, false);

    arr4.clone_from_slice(unsafe{slice::from_raw_parts(b_bytes, 4)});
    let b = match ark_bls12_381::Fr::from_repr(BigInteger256::new(arr4)) {
        Some(v) => v,
        None => return -1,
    };

    //let res = g1.mul(b).into_affine();
    let res = match affine {
        1 => g1.mul(b).into_affine(),
        0 => g1.mul(b).into_affine(),
        //0 => g1.into_projective().mul(b.0).into_affine(),
        _ => { panic!("Invalid"); }
    };

    if !g1.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_neg_bls12_381(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            affine: i32,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bls12_381::G1Affine::new(ax, ay, false);

    let res = match affine {
        1 => g1.neg(),
        0 => g1.into_projective().neg().into_affine(),
        _ => { panic!("Invalid"); }
    };

    if !g1.is_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g2_isoncurve_bls12_381(
            av_bytes: *mut u64,
            aw_bytes: *mut u64,
            ax_bytes: *mut u64,
            ay_bytes: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(av_bytes, 6)});
    let av = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(aw_bytes, 6)});
    let aw = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_381::G2Affine::new(
        ark_bls12_381::Fq2::new(av, ax),
        ark_bls12_381::Fq2::new(aw, ay),
        false);

    if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g2_add_bls12_381(
            av_bytes: *mut u64,
            aw_bytes: *mut u64,
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            bv_bytes: *mut u64,
            bw_bytes: *mut u64,
            bx_bytes: *mut u64,
            by_bytes: *mut u64,
            affine: i32,
            result_v: *mut u64,
            result_w: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(av_bytes, 6)});
    let av = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(aw_bytes, 6)});
    let aw = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_381::G2Affine::new(
        ark_bls12_381::Fq2::new(av, ax),
        ark_bls12_381::Fq2::new(aw, ay),
        false);

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(bv_bytes, 6)});
    let bv = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(bw_bytes, 6)});
    let bw = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(bx_bytes, 6)});
    let bx = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(by_bytes, 6)});
    let by = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let b = ark_bls12_381::G2Affine::new(
        ark_bls12_381::Fq2::new(bv, bx),
        ark_bls12_381::Fq2::new(bw, by),
        false);

    let res = match affine {
        1 => a.add(b),
        0 => a.into_projective().add(b.into_projective()).into_affine(),
        _ => { panic!("Invalid"); }
    };

    if !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }
    if !b.is_on_curve() || !b.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }


    let res_bn_v : BigInteger384 = res.x.c0.into();
    let res_bn_w : BigInteger384 = res.x.c1.into();
    let res_bn_x : BigInteger384 = res.y.c0.into();
    let res_bn_y : BigInteger384 = res.y.c1.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_v.as_ref().as_ptr(), result_v, 6);
        ptr::copy_nonoverlapping(res_bn_w.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_w, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g2_mul_bls12_381(
            av_bytes: *mut u64,
            aw_bytes: *mut u64,
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            b_bytes: *mut u64,
            affine: i32,
            result_v: *mut u64,
            result_w: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];
    let mut arr4: [u64; 4] = [0; 4];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(av_bytes, 6)});
    let av = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(aw_bytes, 6)});
    let aw = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let g2 = ark_bls12_381::G2Affine::new(
        ark_bls12_381::Fq2::new(av, ax),
        ark_bls12_381::Fq2::new(aw, ay),
        false);

    arr4.clone_from_slice(unsafe{slice::from_raw_parts(b_bytes, 4)});
    let b = match ark_bls12_381::Fr::from_repr(BigInteger256::new(arr4)) {
        Some(v) => v,
        None => return -1,
    };

    let res = match affine {
        1 => g2.mul(b).into_affine(),
        0 => g2.mul(b).into_affine(),
        //0 => g2.into_projective().mul(b.0).into_affine(),
        _ => { panic!("Invalid"); }
    };

    let res_bn_v : BigInteger384 = res.x.c0.into();
    let res_bn_w : BigInteger384 = res.x.c1.into();
    let res_bn_x : BigInteger384 = res.y.c0.into();
    let res_bn_y : BigInteger384 = res.y.c1.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_v.as_ref().as_ptr(), result_v, 6);
        ptr::copy_nonoverlapping(res_bn_w.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_w, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g2_neg_bls12_381(
            av_bytes: *mut u64,
            aw_bytes: *mut u64,
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            affine: i32,
            result_v: *mut u64,
            result_w: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(av_bytes, 6)});
    let av = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(aw_bytes, 6)});
    let aw = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_381::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let g2 = ark_bls12_381::G2Affine::new(
        ark_bls12_381::Fq2::new(av, ax),
        ark_bls12_381::Fq2::new(aw, ay),
        false);

    let res = match affine {
        1 => g2.neg(),
        0 => g2.into_projective().neg().into_affine(),
        _ => { panic!("Invalid"); }
    };

    if !g2.is_on_curve() {
        return -1;
    }

    let res_bn_v : BigInteger384 = res.x.c0.into();
    let res_bn_w : BigInteger384 = res.x.c1.into();
    let res_bn_x : BigInteger384 = res.y.c0.into();
    let res_bn_y : BigInteger384 = res.y.c1.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_v.as_ref().as_ptr(), result_v, 6);
        ptr::copy_nonoverlapping(res_bn_w.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_w, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

/* BLS 12-377 */

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc_bls12_377_fq(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 6)});
    let bn0 = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 6)});
    let bn1 = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bls12_377::Fq::new(BigInteger384::new([0u64; 6]));

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
    } else if op == 8 {
        res = bn0.mul(bn1);
    } else if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 9 {
        res = bn0.neg();
    } else {
        return -1;
    }

    let res_bn : BigInteger384 = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bn.as_ref().as_ptr(), result, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_bignumcalc_bls12_377_fr(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            bn2_bytes: *mut u64,
            result: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = match ark_bls12_377::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = match ark_bls12_377::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let mut res = ark_bls12_377::Fr::new(BigInteger256::new([0u64; 4]));

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
    } else if op == 8 {
        res = bn0.mul(bn1);
    } else if op == 0 {
        res = bn0.add(bn1);
    } else if op == 1 {
        res = bn0.sub(bn1);
    } else if op == 9 {
        res = bn0.neg();
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
pub extern "C" fn arkworks_algebra_g1_isoncurve_bls12_377(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_377::G1Affine::new(ax, ay, false);

    if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_privatetopublic_bls12_377(
            priv_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    let g1 = ark_bls12_377::G1Affine::prime_subgroup_generator();

    arr.clone_from_slice(unsafe{slice::from_raw_parts(priv_bytes, 4)});
    let privv = match ark_bls12_377::Fr::from_repr(BigInteger256::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let res = g1.mul(privv).into_affine();

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_add_bls12_377(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            bx_bytes: *mut u64,
            by_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let a = ark_bls12_377::G1Affine::new(ax, ay, false);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bx_bytes, 6)});
    let bx = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(by_bytes, 6)});
    let by = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let b = ark_bls12_377::G1Affine::new(bx, by, false);


    let res = a.add(b);

    if !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }
    if !b.is_on_curve() || !b.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_mul_bls12_377(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            b_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr6: [u64; 6] = [0; 6];
    let mut arr4: [u64; 4] = [0; 4];

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    arr6.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr6)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bls12_377::G1Affine::new(ax, ay, false);

    arr4.clone_from_slice(unsafe{slice::from_raw_parts(b_bytes, 4)});
    let b = match ark_bls12_377::Fr::from_repr(BigInteger256::new(arr4)) {
        Some(v) => v,
        None => return -1,
    };

    let res = g1.mul(b).into_affine();

    if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn arkworks_algebra_g1_neg_bls12_377(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match ark_bls12_377::Fq::from_repr(BigInteger384::new(arr)) {
        Some(v) => v,
        None => return -1,
    };

    let g1 = ark_bls12_377::G1Affine::new(ax, ay, false);

    let res = g1.neg();

    if !g1.is_on_curve() || !g1.is_in_correct_subgroup_assuming_on_curve() {
        return -1;
    }

    let res_bn_x : BigInteger384 = res.x.into();
    let res_bn_y : BigInteger384 = res.y.into();

    unsafe {
        ptr::copy_nonoverlapping(res_bn_x.as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res_bn_y.as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}
