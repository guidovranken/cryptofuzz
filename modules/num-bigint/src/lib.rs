use std::slice;
use std::ptr;
use num_bigint::BigInt;
use num_traits::{One, Zero, Signed};
use num_integer::Integer;
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_bigint::Sign::{Minus, NoSign, Plus};

#[no_mangle]
pub extern "C" fn rust_num_bigint_bignumcalc(
            op: u64,
            bn0_sign: bool, bn0_bytes: *mut u8, bn0_size: libc::size_t,
            bn1_sign: bool, bn1_bytes: *mut u8, bn1_size: libc::size_t,
            bn2_sign: bool, bn2_bytes: *mut u8, bn2_size: libc::size_t,
            result: *mut u8) -> i32 {
    let bn0 = unsafe { slice::from_raw_parts(bn0_bytes, bn0_size) };
    let bn0 = match bn0_sign {
        true => BigInt::from_bytes_be(Plus, bn0),
        false => BigInt::from_bytes_be(Minus, bn0),
    };

    let bn1 = unsafe { slice::from_raw_parts(bn1_bytes, bn1_size) };
    let bn1 = match bn1_sign {
        true => BigInt::from_bytes_be(Plus, bn1),
        false => BigInt::from_bytes_be(Minus, bn1),
    };

    let bn2 = unsafe { slice::from_raw_parts(bn2_bytes, bn2_size) };
    let bn2 = match bn2_sign {
        true => BigInt::from_bytes_be(Plus, bn2),
        false => BigInt::from_bytes_be(Minus, bn2),
    };

    let res: BigInt;

    if op == 0 {
        res = bn0 + bn1;
    } else if op == 1 {
        res = bn0 - bn1;
    } else if op == 2 {
        res = bn0 * bn1;
    } else if op == 3 {
        if bn1 == Zero::zero() {
            return -1;
        }

        if bn0.sign() != Minus && bn1.sign() != Minus {
            res = bn0 / bn1;
        } else {
            return -1;
        }
    } else if op == 4 {
        if bn1 == Zero::zero() {
            return -1;
        }
        if bn0.sign() != Minus && bn1.sign() != Minus {
            res = bn0 % bn1;
        } else {
            return -1;
        }
    } else if op == 5 {
        if bn0.bits() > 1000 {
            return -1;
        }
        if bn1.bits() > 1000 {
            return -1;
        }
        if bn2.bits() > 1000 {
            return -1;
        }
        if bn2 == Zero::zero() {
            return -1;
        }
        if bn1.sign() == Minus {
            /* Negative exponents are not supported */
            return -1;
        }
        res = bn0.modpow(&bn1, &bn2);
    } else if op == 6 {
        if bn0.sign() == Minus {
            return -1;
        }
        res = bn0.sqrt();
    } else if op == 7 {
        res = bn0 << 1;
    } else if op == 8 {
        res = bn0 & bn1;
    } else if op == 9 {
        res = bn0 | bn1;
    } else if op == 10 {
        res = bn0 ^ bn1;
    } else if op == 11 {
        res = bn0.gcd(&bn1);
    } else if op == 12 {
        if bn0.sign() != Minus && bn1.sign() != Minus {
            res = bn0.lcm(&bn1);
        } else {
            return -1;
        }
    } else if op == 13 {
        if bn0.is_even() {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 14 {
        if bn0.is_odd() {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 15 {
        if bn0 < bn1 {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 16 {
        if bn0 <= bn1 {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 17 {
        if bn0 == bn1 {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 18 {
        if bn0 > bn1 {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 19 {
        if bn0 >= bn1 {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 20 {
        res = BigInt::from_u64(bn0.bits()).unwrap();
    } else if op == 21 {
        let exponent = match bn1.to_u32() {
            Some(_v) => _v,
            None => return -1,
        };
        res = bn0.pow(exponent);
    } else if op == 22 {
        if bn0.sign() != Minus && bn1.sign() != Minus {
            let count = match bn1.to_u128() {
                Some(_v) => _v,
                None => return -1,
            };
            res = bn0 >> count;
        } else {
            return -1;
        }
    } else if op == 23 {
        let pos = match bn1.to_u64() {
            Some(_v) => _v,
            None => return -1,
        };
        if bn0.sign() != Minus {
            let mut tmp = bn0;
            tmp.set_bit(pos, false);
            res = tmp;
        } else {
            return -1;
        }
    } else if op == 24 {
        let pos = match bn1.to_u64() {
            Some(_v) => _v,
            None => return -1,
        };
        if bn0.sign() != Minus {
            let mut tmp = bn0;
            tmp.set_bit(pos, true);
            res = tmp;
        } else {
            return -1;
        }
    } else if op == 25 {
        res = bn0.min(bn1);
    } else if op == 26 {
        res = bn0.max(bn1);
    } else if op == 27 {
        if bn0 == Zero::zero() {
            res = BigInt::from_u64(0).unwrap();
        } else {
            res = BigInt::from_u64(bn0.trailing_zeros().unwrap()).unwrap();
        }
    } else if op == 28 {
        let pos = match bn1.to_u64() {
            Some(_v) => _v,
            None => return -1,
        };

        if bn0.sign() != Minus {
            if bn0.bit(pos) == true {
                res = One::one();
            } else {
                res = Zero::zero();
            }
        } else {
            return -1;
        }
    } else if op == 29 {
        let extgcd = bn0.extended_gcd(&bn1);
        if !extgcd.gcd.is_one() {
            return -1;
        }
        if extgcd.x.is_negative() {
            res = extgcd.x + bn1;
        } else {
            res = extgcd.x;
        }
    } else if op == 30 {
        if bn0.is_zero() == true {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 31 {
        if bn0.is_one() == true {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 32 {
        res = bn0;
    } else if op == 33 {
        res = bn0.cbrt();
    } else if op == 34 {
        res = bn0.abs();
    } else if op == 35 {
        if bn0.sign() == Minus {
            res = One::one();
        } else {
            res = Zero::zero();
        }
    } else if op == 36 {
        let n = match bn1.to_u32() {
            Some(_v) => _v,
            None => return -1,
        };
        if bn0.is_negative() && bn1.is_even() {
            return -1;
        }
        if n == 0 {
            return -1;
        }
        res = bn0.nth_root(n);
    } else if op == 37 {
        if bn0.is_zero() == true {
            return -1;
        }
        if bn1.is_zero() == true {
            return -1;
        }
        res = bn0.extended_gcd(&bn1).x;
    } else if op == 38 {
        if bn0.is_zero() == true {
            return -1;
        }
        if bn1.is_zero() == true {
            return -1;
        }
        res = bn0.extended_gcd(&bn1).y;
    } else {
        return -1;
    }


    let (sign, res_bytes) = res.to_bytes_le();

    if res_bytes.len() > 4000 {
        return -1;
    }

    unsafe {
        ptr::copy_nonoverlapping(res_bytes.as_ptr(), result, res_bytes.len());
    }

    if sign == NoSign || sign == Plus {
        return 0;
    } else {
        return 1;
    }
}
