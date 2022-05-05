from bigint import BigInt3, nondet_bigint3, bigint_mul, UnreducedBigInt5
from alt_bn128_def import P0, P1, P2
from alt_bn128_field import (
    is_zero, FQ12, verify_zero5, fq12_is_zero, nondet_fq12, fq12_one, fq12_diff, fq12_pow_12,
    fq12_pow_3, fq12_zero)
from alt_bn128_g1 import G1Point, compute_doubling_slope, compute_slope
from alt_bn128_g2 import G2Point
from alt_bn128_gt import (
    GTPoint, gt_slope, gt_doubling_slope, twist, g1_to_gt, fq12_mul, gt_double, gt_add)

const ate_loop_count = 29793968203157093288
const log_ate_loop_count = 63

from starkware.cairo.common.registers import get_label_location

func get_loop_count_bits(index : felt) -> (bits : felt):
    let (data) = get_label_location(bits)
    let bit_array = cast(data, felt*)
    return (bit_array[index])

    bits:
    dw 0
    dw 0
    dw 0
    dw 1
    dw 0
    dw 1
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 0
    dw 0
    dw 1
    dw 1
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 0
    dw 1
    dw 1
    dw 1
    dw 1
    dw 1
    dw 0
    dw 1
    dw 1
    dw 0
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 1
    dw 0
    dw 0
    dw 1
    dw 1
    dw 1
    dw 1
    dw 0
    dw 1
    dw 0
    dw 1
    dw 1
    dw 1
    dw 0
    dw 0
    dw 1
end

func gt_linehelp{range_check_ptr}(pt0 : GTPoint, pt1 : GTPoint, t : GTPoint, slope : FQ12) -> (
        res : FQ12):
    %{
        import sys, os 
        cwd = os.getcwd()
        sys.path.append(cwd)

        from utils.bn128_field import FQ, FQ12
        from utils.bn128_utils import parse_fq12

        x1 = FQ12(list(map(FQ, parse_fq12(ids.pt1.x))))
        y1 = FQ12(list(map(FQ, parse_fq12(ids.pt1.y))))
        xt = FQ12(list(map(FQ, parse_fq12(ids.t.x))))
        yt = FQ12(list(map(FQ, parse_fq12(ids.t.y))))

        res = (slope * (xt - x1) - (yt - y1))
        value = list(map(lambda x: x.n, res.coeffs))
    %}
    let (res : FQ12) = nondet_fq12()
    # TODO VERIFY
    # let (x_diff_slope : UnreducedBigInt5) = bigint_mul(
    #     BigInt3(d0=t.x.d0 - pt1.x.d0, d1=t.x.d1 - pt1.x.d1, d2=t.x.d2 - pt1.x.d2), slope)

    # verify_zero5(
    #     UnreducedBigInt5(
    #     d0=x_diff_slope.d0 - t.y.d0 + pt0.x.d0 - res.d0,
    #     d1=x_diff_slope.d1 - t.y.d1 + pt0.x.d1 - res.d1,
    #     d2=x_diff_slope.d2 - t.y.d2 + pt0.x.d2 - res.d2,
    #     d3=x_diff_slope.d3,
    #     d4=x_diff_slope.d4))

    return (res)
end

func gt_linefunc{range_check_ptr}(pt0 : GTPoint, pt1 : GTPoint, t : GTPoint) -> (res : FQ12):
    let (x_diff : FQ12) = fq12_diff(pt0.x, pt1.x)
    let (same_x : felt) = fq12_is_zero(x_diff)
    if same_x == 0:
        let (slope : FQ12) = gt_slope(pt0, pt1)
        let (res : FQ12) = gt_linehelp(pt0, pt1, t, slope)
        return (res=res)
    else:
        let (y_diff : FQ12) = fq12_diff(pt0.y, pt1.y)
        let (same_y : felt) = fq12_is_zero(y_diff)
        if same_y == 1:
            let (slope : FQ12) = gt_doubling_slope(pt0)
            let (res : FQ12) = gt_linehelp(pt0, pt1, t, slope)
            return (res=res)
        else:
            let (res : FQ12) = fq12_diff(t.x, pt0.x)
            return (res=res)
        end
    end
end

func miller_loop{range_check_ptr}(Q : GTPoint, P : GTPoint, R : GTPoint, n : felt, f : FQ12) -> (
        res : FQ12):
    # END OF LOOP
    if n == 0:
        alloc_locals
        let modulus = BigInt3(P0, P1, P2)
        let (_, local q1x) = fq12_pow_3(Q.x, modulus)
        let (_, local q1y) = fq12_pow_3(Q.y, modulus)
        let Q1 = GTPoint(q1x, q1y)

        let (local lfRQ1P : FQ12) = gt_linefunc(R, Q1, P)
        let (local newR : GTPoint) = gt_add(R, Q1)

        let (_, local nq2x) = fq12_pow_3(q1x, modulus)
        let (_, local q2y) = fq12_pow_3(q1y, modulus)
        let (zero) = fq12_zero()
        let (nq2y) = fq12_diff(zero, q2y)
        let nQ2 = GTPoint(nq2x, nq2y)

        let (local lfnQ2P : FQ12) = gt_linefunc(newR, nQ2, P)
        let (local f_1 : FQ12) = fq12_mul(f, lfRQ1P)
        let (f_2 : FQ12) = fq12_mul(f_1, lfnQ2P)
        # final exponentiation
        return final_exponentiation(f_2)
    end

    alloc_locals
    # inner loop
    let (bit) = get_loop_count_bits(n - 1)

    let (local f_sqr : FQ12) = fq12_mul(f, f)
    let (local lfRRP : FQ12) = gt_linefunc(R, R, P)
    let (local f_sqr_l : FQ12) = fq12_mul(f_sqr, lfRRP)
    let (twoR : GTPoint) = gt_double(R)
    if bit == 0:
        return miller_loop(Q=Q, P=P, R=twoR, n=n - 1, f=f_sqr_l)
    else:
        let (local lfRQP : FQ12) = gt_linefunc(twoR, Q, P)
        let (local new_f : FQ12) = fq12_mul(f_sqr_l, lfRQP)
        let (twoRpQ : GTPoint) = gt_add(twoR, Q)
        return miller_loop(Q=Q, P=P, R=twoRpQ, n=n - 1, f=new_f)
    end
end

func pairing{range_check_ptr}(Q : G2Point, P : G1Point) -> (res : FQ12):
    alloc_locals
    let (local twisted_Q : GTPoint) = twist(Q)
    let (local f : FQ12) = fq12_one()
    let (cast_P : GTPoint) = g1_to_gt(P)
    return miller_loop(Q=twisted_Q, P=cast_P, R=twisted_Q, n=log_ate_loop_count + 1, f=f)
end

func final_exponentiation{range_check_ptr}(x : FQ12) -> (res : FQ12):
    let final_exponent = FQ12(
        BigInt3(d0=6212946889023415678071072, d1=45799200417935711304343445, d2=42770771512020533619734522),
        BigInt3(d0=59170517635015779814843574, d1=69861904660805168774244518, d2=18175251611003261941144987),
        BigInt3(d0=6224840365716485556659866, d1=72079669560153613533475076, d2=54097091982365706908871098),
        BigInt3(d0=23778027891331508348714600, d1=27070990064893031605816996, d2=66880530963181666257122137),
        BigInt3(d0=6428453163241839293638384, d1=3915066362894641347128887, d2=57669624004488276782181297),
        BigInt3(d0=67978089800637315191356650, d1=51071509339440355656395904, d2=68120774182643646161376785),
        BigInt3(d0=25088979566862161605950544, d1=63116802240563251842289738, d2=36250774203703337112865410),
        BigInt3(d0=42045420448204954441533445, d1=76593899932297329118450698, d2=60079122095221526332763037),
        BigInt3(d0=46087482279252059585677525, d1=41252762411239220367854994, d2=14786342199147618000549637),
        BigInt3(d0=27452466885733176020010742, d1=32571718558893095687996369, d2=74875694450552131089070851),
        BigInt3(d0=72489332814153009192769011, d1=9971105602881718038104912, d2=203128949104),
        BigInt3(d0=0, d1=0, d2=0))

    return fq12_pow_12(x, final_exponent)
end
