use uint::construct_uint;
use std::convert::TryFrom;

mod ids;
use crate::ids::{*};

construct_uint! {
    pub struct U256(4);
}

#[no_mangle]
pub extern "C" fn rust_uint_bigint_bignumcalc(
            op: u64,
            bn0: &[u8; 32],
            bn1: &[u8; 32],
            modifier: u8,
            result: &mut [u8; 32]) -> i32 {
    let bn0 = U256::from_big_endian(&*bn0);
    let bn1 = U256::from_big_endian(&*bn1);

    let res: U256;

    if is_add(op) {
        res = bn0.overflowing_add(bn1).0;
    } else if is_sub(op) {
        res = bn0.overflowing_sub(bn1).0;
    } else if is_mul(op) {
        res = bn0.overflowing_mul(bn1).0;
    } else if is_div(op) {
        if bn1.is_zero() {
            return -1;
        }
        res = bn0.div_mod(bn1).0;
    } else if is_mod(op) {
        if bn1.is_zero() {
            return -1;
        }
        res = bn0.div_mod(bn1).1;
    } else if is_exp(op) {
        res = bn0.overflowing_pow(bn1).0;
    } else if is_rshift(op) {
        let count = match usize::try_from(bn1) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        res = bn0 >> count;
    } else if is_lshift(op) {
        let count = match usize::try_from(bn1) {
            Ok(_v) => _v,
            Err(_e) => return -1,
        };
        res = bn0 << count;
    } else if is_or(op) {
        res = bn0 | bn1;
    } else if is_xor(op) {
        res = bn0 ^ bn1;
    } else if is_and(op) {
        res = bn0 & bn1;
    } else if is_isone(op) {
        if bn0 == U256::one() {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_iszero(op) {
        if bn0.is_zero() {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_isgt(op) {
        if bn0 > bn1 {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_isgte(op) {
        if bn0 >= bn1 {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_islt(op) {
        if bn0 < bn1 {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_islte(op) {
        if bn0 <= bn1 {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else if is_iseq(op) {
        if bn0 == bn1 {
            res = U256::one();
        } else {
            res = U256::zero();
        }
    } else {
        return -1;
    }

    res.to_big_endian(result);

    return 0;
}
