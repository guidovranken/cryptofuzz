use std::slice;
use std::ptr;

use pairing_ce::bls12_381;
use pairing_ce::ff::PrimeField;
use pairing_ce::CurveAffine;
use pairing_ce::CurveProjective;
use pairing_ce::ff::Field;

#[no_mangle]
pub extern "C" fn pairing_ce_g1_isoncurve(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    if ax.is_zero() {
        return -1;
    }

    let a = match bls12_381::G1Affine::from_xy_checked(ax, ay) {
        Ok(v) => v,
        Err(..) => return 0,
    };

    /* is_in_correct_subgroup_assuming_on_curve is private */
    /*
    if a.is_in_correct_subgroup_assuming_on_curve() == false {
        return 0;
    } else {
        return 1;
    }
    */

    return -1;
}

#[no_mangle]
pub extern "C" fn pairing_ce_g1_add(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            bx_bytes: *mut u64,
            by_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    let mut a = match bls12_381::G1Affine::from_xy_checked(ax, ay) {
        Ok(v) => v.into_projective(),
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bx_bytes, 6)});
    let bx = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(by_bytes, 6)});
    let by = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    let b = match bls12_381::G1Affine::from_xy_checked(bx, by) {
        Ok(v) => v.into_projective(),
        Err(..) => return -1
    };

    a.add_assign(&b);

    let res = a.into_affine().into_xy_unchecked();
    unsafe {
        ptr::copy_nonoverlapping(res.0.into_repr().as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res.1.into_repr().as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn pairing_ce_g1_mul(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            b_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];
    let mut arr4: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    let mut a = match bls12_381::G1Affine::from_xy_checked(ax, ay) {
        Ok(v) => v.into_projective(),
        Err(..) => return -1
    };

    arr4.clone_from_slice(unsafe{slice::from_raw_parts(b_bytes, 4)});
    let b = match bls12_381::Fr::from_repr(bls12_381::FrRepr(arr4)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    a.mul_assign(b);

    let res = a.into_affine().into_xy_unchecked();
    unsafe {
        ptr::copy_nonoverlapping(res.0.into_repr().as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res.1.into_repr().as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn pairing_ce_g1_neg(
            ax_bytes: *mut u64,
            ay_bytes: *mut u64,
            result_x: *mut u64,
            result_y: *mut u64) -> i32 {
    let mut arr: [u64; 6] = [0; 6];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ax_bytes, 6)});
    let ax = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    arr.clone_from_slice(unsafe{slice::from_raw_parts(ay_bytes, 6)});
    let ay = match bls12_381::Fq::from_repr(bls12_381::FqRepr(arr)) {
        Ok(v) => v,
        Err(..) => return -1
    };

    let mut a = match bls12_381::G1Affine::from_xy_checked(ax, ay) {
        Ok(v) => v.into_projective(),
        Err(..) => return -1
    };

    a.negate();

    let res = a.into_affine().into_xy_unchecked();
    unsafe {
        ptr::copy_nonoverlapping(res.0.into_repr().as_ref().as_ptr(), result_x, 6);
        ptr::copy_nonoverlapping(res.1.into_repr().as_ref().as_ptr(), result_y, 6);
    }

    return 0;
}
