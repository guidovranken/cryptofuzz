extern crate ff;

use crate::ff::PrimeField;
use std::slice;
use std::ptr;
use crate::ff::Field;

#[derive(PrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "big"]
struct Fp([u64; 4]);

#[no_mangle]
pub extern "C" fn cryptofuzz_ff_bignumcalc(
            op: u64,
            bn0_bytes: *mut u8,
            result: *mut u8) -> i32 {
    let mut arr: [u8; 32] = [0; 32];

    arr.clone_from_slice(unsafe{slice::from_raw_parts(bn0_bytes, 32)});
    let _bn0 = Fp::from_repr(FpRepr(arr));
    let bn0: Fp;
    if _bn0.is_none().into() {
        return -1;
    } else {
        bn0 = _bn0.unwrap();
    }

    let _res: Fp;
    if op == 0 {
        _res = bn0.square();
    } else if op == 1 {
        let tmp = bn0.invert();
        if tmp.is_none().into() {
            _res = Fp::from(0);
        } else {
            _res = tmp.unwrap();
        }
    } else if op == 2 {
        let tmp = bn0.sqrt();
        if tmp.is_none().into() {
            _res = Fp::from(0);
        } else {
            _res = tmp.unwrap().square();
        }
    } else if op == 3 {
        _res = bn0.double();
    } else {
        return -1;
    }
    let res: [u8; 32] = _res.to_repr().0;
    unsafe {
        ptr::copy_nonoverlapping(res.as_ptr(), result, res.len());
    }
    return 0;
}
