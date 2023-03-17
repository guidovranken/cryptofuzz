use pasta_curves::vesta;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::group::ff::Field;
use std::slice;
use std::ptr;

#[no_mangle]
pub extern "C" fn cryptofuzz_pasta_curves_bignumcalc_vesta_fr(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            result: *mut u8) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = vesta::Scalar::from_raw(arr);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = vesta::Scalar::from_raw(arr);

    let mut res = vesta::Scalar::from_raw([0u64; 4]);

    if op == 0 {
        res = bn0 + bn1;
    } else if op == 1 {
        res = bn0 - bn1;
    } else if op == 2 {
        res = bn0 * bn1;
    } else if op == 3 {
        res = bn0.square();
    } else if op == 4 {
        let sqrt = bn0.sqrt();
        if sqrt.is_none().unwrap_u8() == 1 {
            /* retain res == 0 */
        } else {
            res = sqrt.unwrap().square();
        }
    } else {
        return -1;
    }

    let res_bytes : [u8; 32] = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bytes.as_ptr(), result, 32);
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn cryptofuzz_pasta_curves_bignumcalc_vesta_fq(
            op: u64,
            bn0_bytes: *mut u64,
            bn1_bytes: *mut u64,
            result: *mut u8) -> i32 {
    let mut arr: [u64; 4] = [0; 4];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 4)});
    let bn0 = vesta::Base::from_raw(arr);

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn1_bytes, 4)});
    let bn1 = vesta::Base::from_raw(arr);

    let mut res = vesta::Base::from_raw([0u64; 4]);

    if op == 0 {
        res = bn0 + bn1;
    } else if op == 1 {
        res = bn0 - bn1;
    } else if op == 2 {
        res = bn0 * bn1;
    } else if op == 3 {
        res = bn0.square();
    } else if op == 4 {
        let sqrt = bn0.sqrt();
        if sqrt.is_none().unwrap_u8() == 1 {
            /* retain res == 0 */
        } else {
            res = sqrt.unwrap().square();
        }
    } else {
        return -1;
    }

    let res_bytes : [u8; 32] = res.into();
    unsafe {
        ptr::copy_nonoverlapping(res_bytes.as_ptr(), result, 32);
    }

    return 0;
}
