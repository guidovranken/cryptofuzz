from bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, bigint_div_mod, verify_urbigint5_zero
from param_def import BASE

func verify_urbigInt3_zero{range_check_ptr}(val : UnreducedBigInt3, n : BigInt3):
    verify_urbigint5_zero(UnreducedBigInt5(d0=val.d0, d1=val.d1, d2=val.d2, 0, 0), n)
    return ()
end

#return 1 if x ==0 mod n
func is_urbigInt3_zero{range_check_ptr}(x : BigInt3, n : BigInt3) -> (res : felt):
    let (xn) = bigint_div_mod(UnreducedBigInt5(d0=x.d0, d1=x.d1, d2=x.d2, 0, 0), UnreducedBigInt3(1, 0, 0), n)
    if xn.d0 == 0:
        if xn.d1 == 0:
            if xn.d2 == 0:
                return (res = 1)
            end
        end
    end
    return (res = 0)
end