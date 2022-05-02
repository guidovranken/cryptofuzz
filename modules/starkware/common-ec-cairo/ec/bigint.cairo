from param_def import BASE, P0, P1, P2
# Represents an integer defined by
#   d0 + BASE * d1 + BASE**2 * d2.
# Note that the limbs (d_i) are NOT restricted to the range [0, BASE) and in particular they
# can be negative.
# In most cases this is used to represent a elliptic curve field element.
struct UnreducedBigInt3:
    member d0 : felt
    member d1 : felt
    member d2 : felt
end

# Same as UnreducedBigInt3, except that d0, d1 and d2 must be in the range [0, 3 * BASE).
# In most cases this is used to represent a elliptic curve field element.
struct BigInt3:
    member d0 : felt
    member d1 : felt
    member d2 : felt
end

# Represents a big integer: sum_i(BASE**i * d_i).
# Note that the limbs (d_i) are NOT restricted to the range [0, BASE) and in particular they
# can be negative.
struct UnreducedBigInt5:
    member d0 : felt
    member d1 : felt
    member d2 : felt
    member d3 : felt
    member d4 : felt
end

# Returns a BigInt3 instance whose value is controlled by a prover hint.
#
# Soundness guarantee: each limb is in the range [0, 3 * BASE).
# Completeness guarantee (honest prover): the value is in reduced form and in particular,
# each limb is in the range [0, BASE).
#
# Hint arguments: value.
func nondet_bigint3{range_check_ptr}() -> (res : BigInt3):
    # The result should be at the end of the stack after the function returns.
    let res : BigInt3 = [cast(ap + 5, BigInt3*)]
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import split
        segments.write_arg(ids.res.address_, split(value))
    %}
    # The maximal possible sum of the limbs, assuming each of them is in the range [0, BASE).
    const MAX_SUM = 3 * (BASE - 1)
    assert [range_check_ptr] = MAX_SUM - (res.d0 + res.d1 + res.d2)

    # Prepare the result at the end of the stack.
    tempvar range_check_ptr = range_check_ptr + 4
    [range_check_ptr - 3] = res.d0; ap++
    [range_check_ptr - 2] = res.d1; ap++
    [range_check_ptr - 1] = res.d2; ap++
    static_assert &res + BigInt3.SIZE == ap
    return (res=res)
end

# Returns (x + y) % P
func bigint_add_mod{range_check_ptr}(x: BigInt3, y: BigInt3, P: BigInt3) -> (res: BigInt3):
    let z = UnreducedBigInt5(
        d0 = x.d0 + y.d0,
        d1 = x.d1 + y.d1,
        d2 = x.d2 + y.d2,
        d3 = x.d3,
        d4 = x.d4
    )

    let (res) = bigint_div_mod(z, UnreducedBigInt3(1, 0, 0), P)
    return (res = res)
end

# Returns (x - y) % P
func bigint_sub_mod{range_check_ptr}(x: BigInt3, y: BigInt3, P: BigInt3) -> (res: BigInt3):
    let z = UnreducedBigInt5(
        d0 = x.d0 - y.d0,
        d1 = x.d1 - y.d1,
        d2 = x.d2 - y.d2,
        d3 = 0,
        d4 = 0
    )

    let (res) = bigint_div_mod(z, UnreducedBigInt3(1, 0, 0), P)
    return (res = res)
end

func bigint_mul(x: BigInt3, y: BigInt3) -> (res: UnreducedBigInt5):
    return (
        UnreducedBigInt5(
            d0 = x.d0 * y.d0,
            d1 = x.d0 * y.d1 + x.d1 * y.d0,
            d2 = x.d0 * y.d2 + x.d1 * y.d1 + x.d2 * y.d0,
            d3 = x.d1 * y.d2 + x.d2 * y.d1,
            d4 = x.d2 * y.d2
        )
    )
end

func bigint_mul_u(x: UnreducedBigInt3, y: BigInt3) -> (res: UnreducedBigInt5):
    return (
        UnreducedBigInt5(
            d0 = x.d0 * y.d0,
            d1 = x.d0 * y.d1 + x.d1 * y.d0,
            d2 = x.d0 * y.d2 + x.d1 * y.d1 + x.d2 * y.d0,
            d3 = x.d1 * y.d2 + x.d2 * y.d1,
            d4 = x.d2 * y.d2
        )
    )
end

# Returns (x * y) % P
func bigint_mul_mod{range_check_ptr}(x: BigInt3, y: BigInt3, P: BigInt3) -> (res: BigInt3):
    let (z) = bigint_mul(x, y)
    let (res) = bigint_div_mod(z, UnreducedBigInt3(1, 0, 0), P)

    return (res=res)
end

# Returns (x / y) % P
func bigint_div_mod{range_check_ptr}(x: UnreducedBigInt5, y: UnreducedBigInt3, P: BigInt3) -> (res: BigInt3):
    alloc_locals
    local flag
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.cairo.common.math_utils import as_int
        from starkware.python.math_utils import div_mod, safe_div

        p = pack(ids.P, PRIME)
        x = pack(ids.x, PRIME) + as_int(ids.x.d3, PRIME) * ids.BASE ** 3 + as_int(ids.x.d4, PRIME) * ids.BASE ** 4
        y = pack(ids.y, PRIME)

        value = res = div_mod(x, y, p)
    %}
    let (res) = nondet_bigint3()

    %{
        k = safe_div(res * y - x, p)
        value = k if k > 0 else 0 - k
        ids.flag = 1 if k > 0 else 0
    %}
    let (k) = nondet_bigint3()
    let (res_y) = bigint_mul_u(y, res)
    let (k_p) = bigint_mul(k, P)

    tempvar carry1 = (res_y.d0 - (2 * flag - 1) * k_p.d0 - x.d0) / BASE
    assert [range_check_ptr + 0] = carry1 + 2 ** 127

    tempvar carry2 = (res_y.d1 - (2 * flag - 1) * k_p.d1 - x.d1 + carry1) / BASE
    assert [range_check_ptr + 1] = carry2 + 2 ** 127

    tempvar carry3 = (res_y.d2 - (2 * flag - 1) * k_p.d2 - x.d2 + carry2) / BASE
    assert [range_check_ptr + 2] = carry3 + 2 ** 127

    tempvar carry4 = (res_y.d3 - (2 * flag - 1) * k_p.d3 - x.d3 + carry3) / BASE
    assert [range_check_ptr + 3] = carry4 + 2 ** 127

    assert res_y.d4 - (2 * flag - 1) * k_p.d4 - x.d4 + carry4 = 0
    let range_check_ptr = range_check_ptr + 4

    return (res=res)
end

# Check val = 0 mod n?
func verify_urbigint5_zero{range_check_ptr}(val : UnreducedBigInt5, n : BigInt3):
    let (res) = bigint_div_mod(val, UnreducedBigInt3(1, 0, 0), n)
    assert res.d0 = 0
    assert res.d1 = 0
    assert res.d2 = 0
    return()
end