from bigint import BigInt3

from alt_bn128_g1 import G1Point
from alt_bn128_g1 import ec_add
from alt_bn128_g1 import ec_mul
from alt_bn128_g1 import ec_double

func cryptofuzz_bls_g1_add{range_check_ptr}(
        a : G1Point,
        b : G1Point) -> (res: G1Point):
    let (res) = ec_add(a, b)
    return (res)
end

func cryptofuzz_bls_g1_mul{range_check_ptr}(
        a : G1Point,
        b : BigInt3) -> (res: G1Point):
    let (res) = ec_mul(a, b)
    return (res)
end

func cryptofuzz_bls_g1_dbl{range_check_ptr}(
        a : G1Point) -> (res: G1Point):
    let (res) = ec_double(a)
    return (res)
end
