from bigint import BigInt3
from ec import EcPoint
from ec import ec_add
from ec import ec_mul
from ec import ec_double
from ec import ec_neg
from ec import verify_point

func cryptofuzz_ecc_point_add{range_check_ptr}(
        a : EcPoint,
        b : EcPoint) -> (res: EcPoint):
    let (res) = ec_add(a, b)
    return (res)
end

func cryptofuzz_ecc_point_mul{range_check_ptr}(
        a : EcPoint,
        b : BigInt3) -> (res: EcPoint):
    let (res) = ec_mul(a, b)
    return (res)
end

func cryptofuzz_ecc_point_dbl{range_check_ptr}(
        a : EcPoint) -> (res: EcPoint):
    let (res) = ec_double(a)
    return (res)
end

func cryptofuzz_ecc_point_neg{range_check_ptr}(
        a : EcPoint) -> (res: EcPoint):
    let (res) = ec_neg(a)
    return (res)
end

func cryptofuzz_ecc_validatepubkey{range_check_ptr}(
        a : EcPoint):
    verify_point(a)
    return ()
end
