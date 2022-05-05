%builtins range_check
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from bigint import BigInt3, nondet_bigint3
from alt_bn128_def import N0, N1, N2, P0, P1, P2
from alt_bn128_field import FQ12, is_zero, fq12_is_zero, fq12_one, fq12_pow_3, fq12_pow_12, fq12_mul
from alt_bn128_g1 import G1Point, compute_doubling_slope, ec_double, ec_add, ec_mul, g1
from alt_bn128_g1 import g1_two, g1_three, g1_negone, g1_negtwo, g1_negthree
from alt_bn128_g2 import G2Point, g2, g2_negone
from alt_bn128_gt import GTPoint, g12
from alt_bn128_gt import gt_two, gt_three, gt_negone, gt_negtwo, gt_negthree
from alt_bn128_ecdsa import verify_ecdsa, mul_s_inv
from alt_bn128_pair import gt_linefunc, pairing, final_exponentiation

func gt_linefunc_test{range_check_ptr}():
    alloc_locals
    let (one : GTPoint) = g12()
    let (two : GTPoint) = gt_two()
    let (three : GTPoint) = gt_three()

    let (negone : GTPoint) = gt_negone()
    let (negtwo : GTPoint) = gt_negtwo()
    let (negthree : GTPoint) = gt_negthree()

    let (val) = gt_linefunc(one, two, one)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, two, two)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, two, three)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 0
    let (val) = gt_linefunc(one, two, negthree)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, negone, one)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, negone, two)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 0
    let (val) = gt_linefunc(one, negone, negone)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, one, one)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    let (val) = gt_linefunc(one, one, two)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 0
    let (val) = gt_linefunc(one, one, negtwo)
    let (val_is0) = fq12_is_zero(val)
    assert val_is0 = 1
    %{ print("GT linefunc test passed") %}
    return ()
end

func ecdsa_test{range_check_ptr}():
    let public_key_pt = G1Point(
        BigInt3(0xc505bebf0ed670fa5ae45, 0x36b2ae5bb3ea65786b2adb, 0x1aea85bef3a108a3322fb),
        BigInt3(0x123ebd558a24597cd41241, 0x1e6a1a0d4c134ea9b90bc8, 0x2bda5f6606e99ae96be86))

    let r = BigInt3(0x30fe324162d69e7a2df8a7, 0x21b6b44f128ec090ee24da, 0x2de2c2e65a3caab91185)
    let s = BigInt3(0xa21e2703c2b208405bff8, 0x10c6b092586c347bed269d, 0x1011f2d442e2c65ce89a)
    let msg_hash = BigInt3(
        0x19b120d29c1246446dfdd4, 0x3f1afd887d951181d25adc, 0x51daaedd17508efc249c)

    verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s)
    %{ print("ecdsa test passed") %}
    return ()
end

func pow_test{range_check_ptr}():
    alloc_locals
    let (local g12_tmp) = g12()
    let n = BigInt3(P0 - 1, P1, P2)

    let (_, res) = fq12_pow_3(g12_tmp.x, n)
    let (final) = final_exponentiation(g12_tmp.x)
    %{
        import sys, os
        cwd = os.getcwd()
        sys.path.append(cwd)

        from utils.bn128_utils import print_fq12, print_g12
        print_fq12("g12.x", ids.g12_tmp.x)
        print_fq12("g12.x ** final", ids.final)
    %}
    return ()
end

func pairing_benchmark{range_check_ptr}():
    alloc_locals
    let (local pt_g1 : G1Point) = g1()
    let (pt_g2 : G2Point) = g2()
    %{
        import time
        tic = time.perf_counter()
    %}
    let (p1 : FQ12) = pairing(pt_g2, pt_g1)
    %{
        tac = time.perf_counter()
        print(f"Pairing computed in {tac - tic:0.4f} seconds")
    %}
    return ()
end

func pairing_test{range_check_ptr}():
    alloc_locals
    let (local pt_g1 : G1Point) = g1()
    let (local pt_ng1 : G1Point) = g1_negone()
    let (local pt_g2 : G2Point) = g2()
    let (local pt_ng2 : G2Point) = g2_negone()
    let (local p1 : FQ12) = pairing(pt_g2, pt_g1)
    %{
        import sys, os
        cwd = os.getcwd()
        sys.path.append(cwd)

        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12, print_g12
        res = FQ12(list(map(FQ, parse_fq12(ids.p1))))
        print("pair(g2, g1) =", res)
    %}
    let (local pn1 : FQ12) = pairing(pt_g2, pt_ng1)
    let (local np1 : FQ12) = pairing(pt_ng2, pt_g1)
    let (local mul1) = fq12_mul(p1, pn1)
    let (local mul2) = fq12_mul(p1, np1)
    %{
        res_pn1 = FQ12(list(map(FQ, parse_fq12(ids.pn1))))
        res_np1 = FQ12(list(map(FQ, parse_fq12(ids.np1))))
        print("pair(g2, -g1) =", res_pn1)
        print("pair(-g2, g1) =", res_np1)
        mul1 = FQ12(list(map(FQ, parse_fq12(ids.mul1))))
        mul2 = FQ12(list(map(FQ, parse_fq12(ids.mul1))))
        print("pair(g2, g1) * pair(g2, -g1) =", mul1)
        print("pair(g2, g1) * pair(-g2, g1) =", mul2)
    %}

    %{ print("pairing test passed") %}
    return ()
end

func main{range_check_ptr}():
    # pow_test()
    # gt_linefunc_test()
    # ecdsa_test()
    pairing_benchmark()
    # pairing_test()
    %{ print("all test passed") %}
    return ()
end
