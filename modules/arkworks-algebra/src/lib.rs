use std::slice;
use std::ptr;
use std::convert::TryInto;

use ark_ff::biginteger::BigInteger256;
use ark_ff::BigInteger;

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

    if op == 0 {
        res = bn0;
        res.add_with_carry(&bn1);
    } else if op == 1 {
        res = bn0;
        res.sub_with_borrow(&bn1);
    } else if op == 2 {
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
