#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <alt_bn128.hpp>

namespace cryptofuzz {
namespace module {

polygon_zkevm_prover::polygon_zkevm_prover(void) :
    Module("polygon-zkevm-prover") {
}

namespace polygon_zkevm_prover_detail {
    static AltBn128::Engine e;

    static AltBn128::G1PointAffine LoadG1(const component::G1 g1) {
        AltBn128::G1PointAffine ret;
        AltBn128::F1.fromString(ret.x, g1.first.ToTrimmedString().c_str());
        AltBn128::F1.fromString(ret.y, g1.second.ToTrimmedString().c_str());
        return ret;
    }

    static component::G1 SaveG1(const AltBn128::G1PointAffine& g1) {
        return component::G1{
            AltBn128::F1.toString(g1.x),
            AltBn128::F1.toString(g1.y)
        };
    }

    static component::G1 SaveG1(AltBn128::G1Point& g1) {
        AltBn128::G1PointAffine g1_affine;
        e.g1.copy(g1_affine, g1);
        return SaveG1(g1_affine);
    }

    static AltBn128::G2PointAffine LoadG2(const component::G2 g2) {
        AltBn128::G2PointAffine ret;
        AltBn128::F1.fromString(ret.x.a, g2.first.first.ToTrimmedString().c_str());
        AltBn128::F1.fromString(ret.x.b, g2.second.first.ToTrimmedString().c_str());
        AltBn128::F1.fromString(ret.y.a, g2.first.second.ToTrimmedString().c_str());
        AltBn128::F1.fromString(ret.y.b, g2.second.second.ToTrimmedString().c_str());
        return ret;
    }

    static component::G2 SaveG2(AltBn128::G2PointAffine& g2) {
        const auto x = AltBn128::F1.toString(g2.x.a);
        const auto y = AltBn128::F1.toString(g2.x.b);
        const auto v = AltBn128::F1.toString(g2.y.a);
        const auto w = AltBn128::F1.toString(g2.y.b);
        return component::G2{x, v, y, w};
    }

    static component::G2 SaveG2(AltBn128::G2Point& g2) {
        AltBn128::G2PointAffine g2_affine;
        e.g2.copy(g2_affine, g2);
        return SaveG2(g2_affine);
    }
}

std::optional<component::G1> polygon_zkevm_prover::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    AltBn128::G1PointAffine res;
    auto a = polygon_zkevm_prover_detail::LoadG1(op.a);
    auto b = polygon_zkevm_prover_detail::LoadG1(op.b);

    polygon_zkevm_prover_detail::e.g1.add(res, a, b);

    ret = polygon_zkevm_prover_detail::SaveG1(res);

    return ret;
}

std::optional<component::G1> polygon_zkevm_prover::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    AltBn128::G1Point res;
    std::optional<std::vector<uint8_t>> b;
    std::vector<uint8_t> brev;
    auto a_affine = polygon_zkevm_prover_detail::LoadG1(op.a);
    b = util::DecToBin(op.b.ToTrimmedString());

    CF_CHECK_NE(b, std::nullopt);
    brev = *b;
    std::reverse(brev.begin(), brev.end());

    polygon_zkevm_prover_detail::e.g1.mulByScalar(res, a_affine, brev.data(), brev.size());

    ret = polygon_zkevm_prover_detail::SaveG1(res);

end:
    return ret;
}

std::optional<component::G1> polygon_zkevm_prover::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    AltBn128::G1PointAffine res;
    auto a = polygon_zkevm_prover_detail::LoadG1(op.a);

    polygon_zkevm_prover_detail::e.g1.neg(res, a);

    ret = polygon_zkevm_prover_detail::SaveG1(res);

    return ret;
}

std::optional<bool> polygon_zkevm_prover::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    auto a = polygon_zkevm_prover_detail::LoadG1(op.a);
    auto b = polygon_zkevm_prover_detail::LoadG1(op.b);

    ret = polygon_zkevm_prover_detail::e.g1.eq(a, b);

    return ret;
}

std::optional<component::G2> polygon_zkevm_prover::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    std::optional<component::G2> ret = std::nullopt;

    AltBn128::G2PointAffine res;

    auto a = polygon_zkevm_prover_detail::LoadG2(op.a);
    auto b = polygon_zkevm_prover_detail::LoadG2(op.b);
    polygon_zkevm_prover_detail::e.g2.add(res, a, b);

    ret = polygon_zkevm_prover_detail::SaveG2(res);

    return ret;
}

std::optional<component::G2> polygon_zkevm_prover::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;

    AltBn128::G2Point res;
    std::optional<std::vector<uint8_t>> b;
    std::vector<uint8_t> brev;
    auto a_affine = polygon_zkevm_prover_detail::LoadG2(op.a);
    b = util::DecToBin(op.b.ToTrimmedString());

    CF_CHECK_NE(b, std::nullopt);
    brev = *b;
    std::reverse(brev.begin(), brev.end());

    polygon_zkevm_prover_detail::e.g2.mulByScalar(res, a_affine, brev.data(), brev.size());

    ret = polygon_zkevm_prover_detail::SaveG2(res);

end:
    return ret;
}

std::optional<component::G2> polygon_zkevm_prover::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;

    AltBn128::G2PointAffine res;
    auto a = polygon_zkevm_prover_detail::LoadG2(op.a);

    polygon_zkevm_prover_detail::e.g2.neg(res, a);

    ret = polygon_zkevm_prover_detail::SaveG2(res);

    return ret;
}

std::optional<bool> polygon_zkevm_prover::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    auto a = polygon_zkevm_prover_detail::LoadG2(op.a);
    auto b = polygon_zkevm_prover_detail::LoadG2(op.b);

    ret = polygon_zkevm_prover_detail::e.g2.eq(a, b);

    return ret;
}

std::optional<component::Bignum> polygon_zkevm_prover::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
        AltBn128::FrElement a;
        AltBn128::FrElement b;
        AltBn128::FrElement res;

        AltBn128::Fr.fromString(a, op.bn0.ToTrimmedString().c_str());
        AltBn128::Fr.fromString(b, op.bn1.ToTrimmedString().c_str());

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                AltBn128::Fr.add(res, a, b);
                break;
            case    CF_CALCOP("Sub(A,B)"):
                AltBn128::Fr.sub(res, a, b);
                break;
            case    CF_CALCOP("Mul(A,B)"):
                AltBn128::Fr.mul(res, a, b);
                break;
            case    CF_CALCOP("Sqr(A)"):
                AltBn128::Fr.square(res, a);
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                AltBn128::Fr.inv(res, a);
                break;
            case    CF_CALCOP("Not(A)"):
                AltBn128::Fr.neg(res, a);
                break;
            case    CF_CALCOP("Exp(A,B)"):
                {
                    auto exp = util::DecToBin(op.bn1.ToTrimmedString());
                    CF_CHECK_NE(exp, std::nullopt);
                    AltBn128::Fr.exp(res, a, exp->data(), exp->size());
                }
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                res = AltBn128::Fr.eq(a, b) ? AltBn128::Fr.one() : AltBn128::Fr.zero();
                break;
            case    CF_CALCOP("IsZero(A)"):
                res = AltBn128::Fr.isZero(a) ? AltBn128::Fr.one() : AltBn128::Fr.zero();
                break;
            default:
                return std::nullopt;
        }

        return component::Bignum(AltBn128::Fr.toString(res));
    } else if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
        AltBn128::F1Element a;
        AltBn128::F1Element b;
        AltBn128::F1Element res;

        AltBn128::F1.fromString(a, op.bn0.ToTrimmedString().c_str());
        AltBn128::F1.fromString(b, op.bn1.ToTrimmedString().c_str());

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                AltBn128::F1.add(res, a, b);
                break;
            case    CF_CALCOP("Sub(A,B)"):
                AltBn128::F1.sub(res, a, b);
                break;
            case    CF_CALCOP("Mul(A,B)"):
                AltBn128::F1.mul(res, a, b);
                break;
            case    CF_CALCOP("Sqr(A)"):
                AltBn128::F1.square(res, a);
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                AltBn128::F1.inv(res, a);
                break;
            case    CF_CALCOP("Not(A)"):
                AltBn128::F1.neg(res, a);
                break;
            case    CF_CALCOP("Exp(A,B)"):
                {
                    auto exp = util::DecToBin(op.bn1.ToTrimmedString());
                    CF_CHECK_NE(exp, std::nullopt);
                    AltBn128::F1.exp(res, a, exp->data(), exp->size());
                }
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                res = AltBn128::F1.eq(a, b) ? AltBn128::F1.one() : AltBn128::F1.zero();
                break;
            case    CF_CALCOP("IsZero(A)"):
                res = AltBn128::F1.isZero(a) ? AltBn128::F1.one() : AltBn128::F1.zero();
                break;
            default:
                return std::nullopt;
        }

        return component::Bignum(AltBn128::F1.toString(res));
    }

end:
    return std::nullopt;
}

bool polygon_zkevm_prover::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
