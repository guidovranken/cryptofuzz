#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <math/wide_integer/uintwide_t.h>

namespace cryptofuzz {
namespace module {

wide_integer::wide_integer(void) :
    Module("wide-integer") { }

std::optional<component::Bignum> wide_integer::OpBignumCalc(operation::BignumCalc& op) {
    const std::string max = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    const bool haveMod = op.modulo != std::nullopt &&
        op.modulo->ToTrimmedString() == max;

    if ( haveMod == false ) {
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Div(A,B)"):
            case    CF_CALCOP("Mod(A,B)"):
            case    CF_CALCOP("ExpMod(A,B,C)"):
            case    CF_CALCOP("GCD(A,B)"):
            case    CF_CALCOP("Sqrt(A)"):
            case    CF_CALCOP("Cbrt(A)"):
                break;
            default:
                return std::nullopt;
        }
    }

    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const math::wide_integer::uint256_t bn0(op.bn0.ToTrimmedString().c_str());
    const math::wide_integer::uint256_t bn1(op.bn1.ToTrimmedString().c_str());
    const math::wide_integer::uint256_t bn2(op.bn2.ToTrimmedString().c_str());
    math::wide_integer::uint256_t res;

    CF_CHECK_TRUE(op.bn0.IsLessThan(max));
    CF_CHECK_TRUE(op.bn1.IsLessThan(max));
    CF_CHECK_TRUE(op.bn2.IsLessThan(max));
    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            res = bn0 + bn1;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            res = bn0 - bn1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            res = bn0 * bn1;
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_NE(bn1, 0);
            res = bn0 / bn1;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_CHECK_NE(bn1, 0);
            res = bn0 % bn1;
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            CF_CHECK_NE(bn2, 0);
            res = math::wide_integer::powm(bn0, bn1, bn2);
            break;
        case    CF_CALCOP("GCD(A,B)"):
            CF_CHECK_NE(bn1, 0);
            res = math::wide_integer::gcd(bn0, bn1);
            break;
        case    CF_CALCOP("Sqrt(A)"):
            res = math::wide_integer::sqrt(bn0);
            break;
        case    CF_CALCOP("Cbrt(A)"):
            res = math::wide_integer::cbrt(bn0);
            break;
        default:
            goto end;
    }

    {
        std::stringstream ss;
        ss << res;
        ret = ss.str();
    }
end:
    return ret;
}

bool wide_integer::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
