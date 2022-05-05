from bigint import BigInt3, nondet_bigint3, bigint_mul
from alt_bn128_field import (
    fq_zero, is_zero, FQ12, nondet_fq12, fq12_eq_zero, fq12_sum, fq12_diff, fq12_is_zero, fq12_zero,
    unreducedFQ12)
from alt_bn128_g1 import G1Point
from alt_bn128_g2 import g2, G2Point

struct GTPoint:
    member x : FQ12
    member y : FQ12
end

# TODO Importing this from bn128_field yields a revoked variable (slope) issue
func fq12_mul{range_check_ptr}(a : FQ12, b : FQ12) -> (res : FQ12):
    %{
        import sys, os
        cwd = os.getcwd()
        sys.path.append(cwd)
        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12, print_g12
        a = FQ12(list(map(FQ, parse_fq12(ids.a))))
        b = FQ12(list(map(FQ, parse_fq12(ids.b))))
        value = res = list(map(lambda x: x.n, (a*b).coeffs))
        # print("a*b =", value)
    %}
    let (res) = nondet_fq12()
    # TODO CHECKS
    return (res=res)
end

# ### ADDITION, MULTIPLICATION

func gt_doubling_slope{range_check_ptr}(pt : GTPoint) -> (slope : FQ12):
    %{
        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12

        # Compute the slope.
        x = FQ12(list(map(FQ, parse_fq12(ids.pt.x))))
        y = FQ12(list(map(FQ, parse_fq12(ids.pt.y))))

        slope = (3 * x ** 2) / (2 * y)
        value = list(map(lambda x: x.n, slope.coeffs))
    %}
    let (slope : FQ12) = nondet_fq12()
    # TODO VERIFY
    return (slope=slope)
end

func gt_slope{range_check_ptr}(pt0 : GTPoint, pt1 : GTPoint) -> (slope : FQ12):
    %{
        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12

        # Compute the slope.
        x0 = FQ12(list(map(FQ, parse_fq12(ids.pt0.x))))
        y0 = FQ12(list(map(FQ, parse_fq12(ids.pt0.y))))
        x1 = FQ12(list(map(FQ, parse_fq12(ids.pt1.x))))
        y1 = FQ12(list(map(FQ, parse_fq12(ids.pt1.y))))

        slope = (y0 - y1) / (x0 - x1)
        value = list(map(lambda x: x.n, slope.coeffs))
    %}
    let (slope) = nondet_fq12()

    # TODO verify
    return (slope)
end

# Given a point 'pt' on the elliptic curve, computes pt + pt.
func gt_double{range_check_ptr}(pt : GTPoint) -> (res : GTPoint):
    let (x_is_zero) = fq12_eq_zero(pt.x)
    if x_is_zero == 1:
        return (res=pt)
    end

    let (slope : FQ12) = gt_doubling_slope(pt)
    let (slope_sqr : FQ12) = fq12_mul(slope, slope)
    %{
        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12

        # Compute the slope.
        x = FQ12(list(map(FQ, parse_fq12(ids.pt.x))))
        y = FQ12(list(map(FQ, parse_fq12(ids.pt.y))))
        slope = FQ12(list(map(FQ, parse_fq12(ids.slope))))
        res = slope ** 2 - x * 2
        value = new_x = list(map(lambda x: x.n, res.coeffs))
    %}
    let (new_x : FQ12) = nondet_fq12()

    %{
        new_x = FQ12(list(map(FQ, parse_fq12(ids.new_x))))
        res = slope * (x - new_x) - y
        value = new_x = list(map(lambda x: x.n, res.coeffs))
    %}
    let (new_y : FQ12) = nondet_fq12()

    # VERIFY
    # verify_zero5(
    #     UnreducedBigInt5(
    #     d0=slope_sqr.d0 - new_x.d0 - 2 * pt.x.d0,
    #     d1=slope_sqr.d1 - new_x.d1 - 2 * pt.x.d1,
    #     d2=slope_sqr.d2 - new_x.d2 - 2 * pt.x.d2,
    #     d3=slope_sqr.d3,
    #     d4=slope_sqr.d4))

    # let (x_diff_slope : UnreducedBigInt5) = bigint_mul(
    #     BigInt3(d0=pt.x.d0 - new_x.d0, d1=pt.x.d1 - new_x.d1, d2=pt.x.d2 - new_x.d2), slope)

    # verify_zero5(
    #     UnreducedBigInt5(
    #     d0=x_diff_slope.d0 - pt.y.d0 - new_y.d0,
    #     d1=x_diff_slope.d1 - pt.y.d1 - new_y.d1,
    #     d2=x_diff_slope.d2 - pt.y.d2 - new_y.d2,
    #     d3=x_diff_slope.d3,
    #     d4=x_diff_slope.d4))

    return (GTPoint(new_x, new_y))
end

func fast_gt_add{range_check_ptr}(pt0 : GTPoint, pt1 : GTPoint) -> (res : GTPoint):
    let (pt0_x_is_zero) = fq12_eq_zero(pt0.x)
    if pt0_x_is_zero == 1:
        return (pt1)
    end
    let (pt1_x_is_zero) = fq12_eq_zero(pt1.x)
    if pt1_x_is_zero == 1:
        return (pt1)
    end

    let (slope : FQ12) = gt_slope(pt0, pt1)
    let (slope_sqr : FQ12) = fq12_mul(slope, slope)

    %{
        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12

        # Compute the slope.
        x0 = FQ12(list(map(FQ, parse_fq12(ids.pt0.x))))
        x1 = FQ12(list(map(FQ, parse_fq12(ids.pt1.x))))
        y0 = FQ12(list(map(FQ, parse_fq12(ids.pt0.y))))
        slope = FQ12(list(map(FQ, parse_fq12(ids.slope))))

        res = slope ** 2 - x0 - x1
        value = new_x = list(map(lambda x: x.n, res.coeffs))
    %}
    let (new_x : FQ12) = nondet_fq12()

    %{
        new_x = res
        res = slope * (x0 - new_x) - y0
        value = new_x = list(map(lambda x: x.n, res.coeffs))
    %}
    let (new_y : FQ12) = nondet_fq12()

    # verify_zero5(
    #     UnreducedBigInt5(
    #     d0=slope_sqr.d0 - new_x.d0 - pt0.x.d0 - pt1.x.d0,
    #     d1=slope_sqr.d1 - new_x.d1 - pt0.x.d1 - pt1.x.d1,
    #     d2=slope_sqr.d2 - new_x.d2 - pt0.x.d2 - pt1.x.d2,
    #     d3=slope_sqr.d3,
    #     d4=slope_sqr.d4))

    # let (x_diff_slope : UnreducedBigInt5) = bigint_mul(
    #     BigInt3(d0=pt0.x.d0 - new_x.d0, d1=pt0.x.d1 - new_x.d1, d2=pt0.x.d2 - new_x.d2), slope)

    # verify_zero5(
    #     UnreducedBigInt5(
    #     d0=x_diff_slope.d0 - pt0.y.d0 - new_y.d0,
    #     d1=x_diff_slope.d1 - pt0.y.d1 - new_y.d1,
    #     d2=x_diff_slope.d2 - pt0.y.d2 - new_y.d2,
    #     d3=x_diff_slope.d3,
    #     d4=x_diff_slope.d4))

    return (GTPoint(new_x, new_y))
end

func gt_add{range_check_ptr}(pt0 : GTPoint, pt1 : GTPoint) -> (res : GTPoint):
    let (x_diff) = fq12_diff(pt0.x, pt1.x)
    let (same_x : felt) = fq12_is_zero(x_diff)
    if same_x == 0:
        return fast_gt_add(pt0, pt1)
    end

    # We have pt0.x = pt1.x. This implies pt0.y = ±pt1.y.
    # Check whether pt0.y = -pt1.y.
    let (y_sum) = fq12_sum(pt0.x, pt0.y)
    let (opposite_y : felt) = fq12_is_zero(y_sum)
    if opposite_y != 0:
        # pt0.y = -pt1.y.
        # Note that the case pt0 = pt1 = 0 falls into this branch as well.
        let (zero_12) = fq12_zero()
        let ZERO_POINT = GTPoint(zero_12, zero_12)
        return (ZERO_POINT)
    else:
        # pt0.y = pt1.y.
        return gt_double(pt0)
    end
end

# ### CASTING G1 INTO GT

func g1_to_gt{range_check_ptr}(pt : G1Point) -> (res : GTPoint):
    # Point should not be zero
    alloc_locals
    let (x_iszero) = is_zero(pt.x)
    let (y_iszero) = is_zero(pt.y)
    assert x_iszero + y_iszero = 0

    let (zero : BigInt3) = fq_zero()
    return (
        GTPoint(
        x=FQ12(pt.x, zero, zero, zero,
            zero, zero, zero, zero,
            zero, zero, zero, zero),
        y=FQ12(pt.y, zero, zero, zero,
            zero, zero, zero, zero,
            zero, zero, zero, zero)))
end

# ### TWISTING G2 INTO GT

func twist{range_check_ptr}(P : G2Point) -> (res : GTPoint):
    let (zero : BigInt3) = fq_zero()
    tempvar x0 = P.x.e0
    tempvar x1 = P.x.e1

    let xx = BigInt3(d0=x0.d0 - 9 * x1.d0, d1=x0.d1 - 9 * x1.d1, d2=x0.d2 - 9 * x1.d2)
    let nxw2 = FQ12(zero, zero, xx, zero, zero, zero, zero, zero, x1, zero, zero, zero)

    tempvar y0 = P.y.e0
    tempvar y1 = P.y.e1
    let yy = BigInt3(d0=y0.d0 - 9 * y1.d0, d1=y0.d1 - 9 * y1.d1, d2=y0.d2 - 9 * y1.d2)
    let nyw3 = FQ12(zero, zero, zero, yy, zero, zero, zero, zero, zero, y1, zero, zero)

    return (res=GTPoint(x=nxw2, y=nyw3))
end

# CONSTANTS
func g12{range_check_ptr}() -> (res : GTPoint):
    let g2_tmp : G2Point = g2()
    let res : GTPoint = twist(g2_tmp)
    return (res=res)
end

func gt_two() -> (res : GTPoint):
    return (
        GTPoint(
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=66531434795446507742202402, d1=57810563030407162761699450, d2=3024423940099633003033660),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=29266951114122318337060217, d1=8315677858884295077185307, d2=2436188124856487536975890),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            ),
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=20729108619955071395783599, d1=33713532092400076519474348, d2=1387780998518836325215322), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=37820632520797176012333394, d1=58429338205645183884307771, d2=1916850345724626333016760), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            )))
end

func gt_three() -> (res : GTPoint):
    return (
        GTPoint(
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=60558478434004798536211741, d1=43863242049195550535444726, d2=489660925987493189701501),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=68458519662193915565862533, d1=8714965904636858911272353, d2=1214966188589858263872793),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            ),
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=62542305924506548566602652, d1=11947492361179029427546200, d2=2636020001628383667142327), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=64470951246555278864748978, d1=61710966665510361729249574, d2=160010759829214388101887), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            )))
end

func gt_negone() -> (res : GTPoint):
    return (
        GTPoint(
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=37098765567079062928113790, d1=75069397608736819304955002, d2=2716309570043849407818057),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=50657168248156029357068994, d1=75996009454876762764004566, d2=1931027739743020521039371),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            ),
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=31925659635663368785745730, d1=76797642075525941605650950, d2=1061992001333544670783866), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=75234859396250709295523308, d1=58200249186681967413131230, d2=2974432145097327839591194), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            )))
end

func gt_negtwo() -> (res : GTPoint):
    return (
        GTPoint(
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=66531434795446507742202402, d1=57810563030407162761699450, d2=3024423940099633003033660),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=29266951114122318337060217, d1=8315677858884295077185307, d2=2436188124856487536975890),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            ),
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=39464779894232690824419736, d1=71283675355909246543773941, d2=2268601696092355443562665), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=22373255993390586207869941, d1=46567869242664139178940518, d2=1739532348886565435761227), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            )))
end

func gt_negthree() -> (res : GTPoint):
    return (
        GTPoint(
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=60558478434004798536211741, d1=43863242049195550535444726, d2=489660925987493189701501),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=68458519662193915565862533, d1=8714965904636858911272353, d2=1214966188589858263872793),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            ),
        FQ12(
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=75022835045017480834795947, d1=15678462631794026454506824, d2=1020362692982808101635661), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            BigInt3(d0=73094189722968750536649621, d1=43286240782798961333998714, d2=3496371934781977380676100), BigInt3(d0=0, d1=0, d2=0), BigInt3(d0=0, d1=0, d2=0),
            )))
end
