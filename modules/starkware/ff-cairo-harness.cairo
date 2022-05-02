from bigint import BigInt3
from bigint import UnreducedBigInt3
from bigint import UnreducedBigInt5
#from bigint import bigint_add_mod
from bigint import bigint_sub_mod
from bigint import bigint_mul
from bigint import bigint_mul_u
from bigint import bigint_div_mod
from bigint import bigint_mul_mod

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.serialize import serialize_word

#func cryptofuzz_bigint_add_mod{range_check_ptr}(
#        a : BigInt3,
#        b : BigInt3,
#        c : BigInt3) -> (res: BigInt3):
#    let (res) = bigint_add_mod(a, b, c)
#    return (res)
#end

func cryptofuzz_bigint_sub_mod{range_check_ptr}(
        a : BigInt3,
        b : BigInt3,
        c : BigInt3) -> (res: BigInt3):
    let (res) = bigint_sub_mod(a, b, c)
    return (res)
end

func cryptofuzz_bigint_mul{range_check_ptr}(
        a : BigInt3,
        b : BigInt3) -> (res: UnreducedBigInt5):
    let (res) = bigint_mul(a, b)
    return (res)
end

func cryptofuzz_bigint_mul_u{range_check_ptr}(
        a : UnreducedBigInt3,
        b : BigInt3) -> (res: UnreducedBigInt5):
    let (res) = bigint_mul_u(a, b)
    return (res)
end

func cryptofuzz_bigint_mul_mod{range_check_ptr}(
        a : BigInt3,
        b : BigInt3,
        c : BigInt3) -> (res: BigInt3):
    let (res) = bigint_mul_mod(a, b, c)
    return (res)
end

func cryptofuzz_bigint_div_mod{range_check_ptr}(
        a : UnreducedBigInt5,
        b : UnreducedBigInt3,
        c : BigInt3) -> (res: BigInt3):
    let (res) = bigint_div_mod(a, b, c)
    return (res)
end

func cryptofuzz_test_func{range_check_ptr}(
        a : felt,
        b : felt) -> (res: felt):
    assert a*b = 10
    return (a*b)
end
