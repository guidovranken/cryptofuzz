from bigint import BigInt3, UnreducedBigInt3, UnreducedBigInt5, nondet_bigint3, bigint_mul, bigint_div_mod, bigint_sub_mod, verify_urbigint5_zero
from field import verify_urbigInt3_zero, is_urbigInt3_zero
from param_def import BASE, P0, P1, P2, N0, N1, N2, A0, A1, A2, GX0, GX1, GX2, GY0, GY1, GY2

# Represents a point on the elliptic curve.
# The zero point is represented using pt.x=0, as there is no point on the curve with this x value.
struct EcPoint:
    member x : BigInt3
    member y : BigInt3
end

# Returns the slope of the elliptic curve at the given point.
# The slope is used to compute pt + pt.
# Assumption: pt != 0.
func compute_doubling_slope{range_check_ptr}(pt : EcPoint) -> (slope : BigInt3):
    # Note that y cannot be zero: assume that it is, then pt = -pt, so 2 * pt = 0, which
    # contradicts the fact that the size of the curve is odd.
    
    let P = BigInt3(P0, P1, P2)
    let (x_sqr) = bigint_mul(pt.x, pt.x)
    let y_2 = UnreducedBigInt3(
        d0 = pt.y.d0 * 2,
        d1 = pt.y.d1 * 2,
        d2 = pt.y.d2 * 2,
    )

    let (slope) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = x_sqr.d0 * 3 + A0,
            d1 = x_sqr.d1 * 3 + A1,
            d2 = x_sqr.d2 * 3 + A2,
            d3 = x_sqr.d3 * 3,
            d4 = x_sqr.d4 * 3
        ), y_2, P)
    return (slope=slope)
end

# Returns the slope of the line connecting the two given points.
# The slope is used to compute pt0 + pt1.
# Assumption: pt0.x != pt1.x (mod curve_prime).
func compute_slope{range_check_ptr}(pt0 : EcPoint, pt1 : EcPoint) -> (slope : BigInt3):
    let P = BigInt3(P0, P1, P2)
    let x_diff = UnreducedBigInt3(
        d0 = pt0.x.d0 - pt1.x.d0,
        d1 = pt0.x.d1 - pt1.x.d1,
        d2 = pt0.x.d2 - pt1.x.d2
    )
    let y_diff = UnreducedBigInt5(
        d0 = pt0.y.d0 - pt1.y.d0,
        d1 = pt0.y.d1 - pt1.y.d1,
        d2 = pt0.y.d2 - pt1.y.d2,
        d3 = 0,
        d4 = 0
    )
    let (slope) = bigint_div_mod(y_diff, x_diff, P)
    return (slope=slope)
end

# Given a point 'pt' on the elliptic curve, computes pt + pt.
func ec_double{range_check_ptr}(pt : EcPoint) -> (res : EcPoint):
    
    if pt.x.d0 == 0:
        if pt.x.d1 == 0:
            if pt.x.d2 == 0:
                return (pt)
            end
        end
    end
    
    let P = BigInt3(P0, P1, P2)
    let (slope : BigInt3) = compute_doubling_slope(pt)
    let (slope_sqr : UnreducedBigInt5) = bigint_mul(slope, slope)

    let (new_x) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = slope_sqr.d0 - 2 * pt.x.d0,
            d1 = slope_sqr.d1 - 2 * pt.x.d1,
            d2 = slope_sqr.d2 - 2 * pt.x.d2,
            d3 = slope_sqr.d3,
            d4 = slope_sqr.d4
        ), UnreducedBigInt3(1, 0, 0), P)

    let (x_diff_slope : UnreducedBigInt5) = bigint_mul(
        BigInt3(d0=pt.x.d0 - new_x.d0, d1=pt.x.d1 - new_x.d1, d2=pt.x.d2 - new_x.d2), slope)

    let (new_y) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = x_diff_slope.d0 - pt.y.d0,
            d1 = x_diff_slope.d1 - pt.y.d1,
            d2 = x_diff_slope.d2 - pt.y.d2,
            d3 = x_diff_slope.d3,
            d4 = x_diff_slope.d4
        ), UnreducedBigInt3(1, 0, 0), P)

    return (EcPoint(new_x, new_y))
end

# Adds two points on the elliptic curve.
# Assumption: pt0.x != pt1.x (however, pt0 = pt1 = 0 is allowed).
# Note that this means that the function cannot be used if pt0 = pt1
# (use ec_double() in this case) or pt0 = -pt1 (the result is 0 in this case).
func fast_ec_add{range_check_ptr}(pt0 : EcPoint, pt1 : EcPoint) -> (res : EcPoint):
    
    if pt0.x.d0 == 0:
        if pt0.x.d1 == 0:
            if pt0.x.d2 == 0:
                return (pt1)
            end
        end
    end
    if pt1.x.d0 == 0:
        if pt1.x.d1 == 0:
            if pt1.x.d2 == 0:
                return (pt0)
            end
        end
    end
    let P = BigInt3(P0,P1,P2)
    let (slope : BigInt3) = compute_slope(pt0, pt1)
    let (slope_sqr : UnreducedBigInt5) = bigint_mul(slope, slope)
    let (new_x : BigInt3) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = slope_sqr.d0 - pt0.x.d0 - pt1.x.d0,
            d1 = slope_sqr.d1 - pt0.x.d1 - pt1.x.d1,
            d2 = slope_sqr.d2 - pt0.x.d2 - pt1.x.d2,
            d3 = slope_sqr.d3,
            d4 = slope_sqr.d4
        ), UnreducedBigInt3(1, 0, 0), P)
    
    let (x_diff_slope : UnreducedBigInt5) = bigint_mul(
        BigInt3(d0=pt0.x.d0 - new_x.d0, d1=pt0.x.d1 - new_x.d1, d2=pt0.x.d2 - new_x.d2), slope)
    let (new_y) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = x_diff_slope.d0 - pt0.y.d0,
            d1 = x_diff_slope.d1 - pt0.y.d1,
            d2 = x_diff_slope.d2 - pt0.y.d2,
            d3 = x_diff_slope.d3,
            d4 = x_diff_slope.d4
        ), UnreducedBigInt3(1, 0, 0), P)

    return (EcPoint(new_x, new_y))
end

# Same as fast_ec_add, except that the cases pt0 = ±pt1 are supported.
func ec_add{range_check_ptr}(pt0 : EcPoint, pt1 : EcPoint) -> (res : EcPoint):
    
    let P = BigInt3(P0, P1, P2)
    let x_diff = BigInt3(d0=pt0.x.d0 - pt1.x.d0, d1=pt0.x.d1 - pt1.x.d1, d2=pt0.x.d2 - pt1.x.d2)
    let (same_x : felt) = is_urbigInt3_zero(x_diff, P)
    if same_x == 0:
        # pt0.x != pt1.x so we can use fast_ec_add.
        return fast_ec_add(pt0, pt1)
    end
    
    # We have pt0.x = pt1.x. This implies pt0.y = ±pt1.y.
    # Check whether pt0.y = -pt1.y.
    let y_sum = BigInt3(d0=pt0.y.d0 + pt1.y.d0, d1=pt0.y.d1 + pt1.y.d1, d2=pt0.y.d2 + pt1.y.d2)
    let (opposite_y : felt) = is_urbigInt3_zero(y_sum, P)
    if opposite_y != 0:
        # pt0.y = -pt1.y.
        # Note that the case pt0 = pt1 = 0 falls into this branch as well.
        let ZERO_POINT = EcPoint(BigInt3(0, 0, 0), BigInt3(0, 0, 0))
        return (ZERO_POINT)
    else:
        # pt0.y = pt1.y.
        return ec_double(pt0)
    end
end

# Do the transform: Point(x, y) -> Point(x, -y)
func ec_neg{range_check_ptr}(pt : EcPoint) -> (res: EcPoint):
    let (neg_y) = bigint_sub_mod(BigInt3(0, 0, 0), pt.y, BigInt3(P0, P1, P2))
    let res = EcPoint(pt.x, neg_y)
    return (res=res)
end

# Given 0 <= m < 250, a scalar and a point on the elliptic curve, pt,
# verifies that 0 <= scalar < 2**m and returns (2**m * pt, scalar * pt).
func ec_mul_inner{range_check_ptr}(pt : EcPoint, scalar : felt, m : felt) -> (
        pow2 : EcPoint, res : EcPoint):
    
    if m == 0:
        assert scalar = 0
        let ZERO_POINT = EcPoint(BigInt3(0, 0, 0), BigInt3(0, 0, 0))
        return (pow2=pt, res=ZERO_POINT)
    end
    
    alloc_locals
    let (double_pt : EcPoint) = ec_double(pt)
    %{ memory[ap] = (ids.scalar % PRIME) % 2 %}
    
    jmp odd if [ap] != 0; ap++
    return ec_mul_inner(pt=double_pt, scalar=scalar / 2, m=m - 1)
    
    odd:
    let (local inner_pow2 : EcPoint, inner_res : EcPoint) = ec_mul_inner(
        pt=double_pt, scalar=(scalar - 1) / 2, m=m - 1)
    # Here inner_res = (scalar - 1) / 2 * double_pt = (scalar - 1) * pt.
    # Assume pt != 0 and that inner_res = ±pt. We obtain (scalar - 1) * pt = ±pt =>
    # scalar - 1 = ±1 (mod N) => scalar = 0 or 2.
    # In both cases (scalar - 1) / 2 cannot be in the range [0, 2**(m-1)), so we get a
    # contradiction.
    let (res : EcPoint) = fast_ec_add(pt0=pt, pt1=inner_res)
    return (pow2=inner_pow2, res=res)
end

func ec_mul{range_check_ptr}(pt : EcPoint, scalar : BigInt3) -> (res : EcPoint):
    alloc_locals
    let (pow2_0 : EcPoint, local res0 : EcPoint) = ec_mul_inner(pt, scalar.d0, 86)
    let (pow2_1 : EcPoint, local res1 : EcPoint) = ec_mul_inner(pow2_0, scalar.d1, 86)
    let (_, local res2 : EcPoint) = ec_mul_inner(pow2_1, scalar.d2, 84)
    let (res : EcPoint) = ec_add(res0, res1)
    let (res : EcPoint) = ec_add(res, res2)
    return (res)
end

# Verify a point lies on the curve.
# In the EC lib, we don't use `b` parameter explictly,
# so to verify whether a point lies on the curve or not,
# we use `G` to compare.
# y_G^2 - y_pt^2 = x_G^3 - x_pt^3 + a(x_G - x_pt) =>
# (y_G - y_pt)(y_G + y_pt) = (x_G^2 + x_G*x_pt + x_pt^2 + a)(x_G - x_pt)
func verify_point{range_check_ptr}(pt: EcPoint):
    let GX = BigInt3(GX0, GX1, GX2)
    let P = BigInt3(P0, P1, P2)

    let (gx2) = bigint_mul(GX, GX)
    let (gkx_prod) = bigint_mul(pt.x, GX)
    let (kx2) = bigint_mul(pt.x, pt.x)

    let (q) = bigint_div_mod(
        UnreducedBigInt5(
            d0 = gx2.d0 + gkx_prod.d0 + kx2.d0 + A0,
            d1 = gx2.d1 + gkx_prod.d1 + kx2.d1 + A1,
            d2 = gx2.d2 + gkx_prod.d2 + kx2.d2 + A2,
            d3 = gx2.d3 + gkx_prod.d3 + kx2.d3,
            d4 = gx2.d4 + gkx_prod.d4 + kx2.d4
        ), UnreducedBigInt3(1, 0, 0), P)

    # check left == right
    let gky_diff = BigInt3(
        d0 = GY0 - pt.y.d0,
        d1 = GY1 - pt.y.d1,
        d2 = GY2 - pt.y.d2
    )
    let gky_sum = BigInt3(
        d0 = GY0 + pt.y.d0,
        d1 = GY1 + pt.y.d1,
        d2 = GY2 + pt.y.d2
    )
    let gkx_diff = BigInt3(
        d0 = GX0 - pt.x.d0,
        d1 = GX1 - pt.x.d1,
        d2 = GX2 - pt.x.d2
    )
    let (left_diff) = bigint_mul(gky_diff, gky_sum)
    let (right_diff) = bigint_mul(q, gkx_diff)

    verify_urbigint5_zero(
        UnreducedBigInt5(
        d0 = left_diff.d0 - right_diff.d0,
        d1 = left_diff.d1 - right_diff.d1,
        d2 = left_diff.d2 - right_diff.d2,
        d3 = left_diff.d3 - right_diff.d3,
        d4 = left_diff.d4 - right_diff.d4,
    ), P)

    return ()
end