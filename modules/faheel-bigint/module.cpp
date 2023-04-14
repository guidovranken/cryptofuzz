#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include "BigInt.hpp"

namespace cryptofuzz {
namespace module {

faheel_BigInt::faheel_BigInt(void) :
    Module("faheel-BigInt") { }

std::optional<component::Bignum> faheel_BigInt::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const BigInt bn0 = BigInt(op.bn0.ToString(ds));
    const BigInt bn1 = BigInt(op.bn1.ToString(ds));
    BigInt res;

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
            CF_CHECK_LTE(op.bn0.GetSize(), 600);
            CF_CHECK_NE(abs(bn1), BigInt(0));
            res = bn0 / bn1;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_CHECK_LTE(op.bn0.GetSize(), 600);
            CF_CHECK_NE(abs(bn1), BigInt(0));
            res = bn0 % bn1;
            break;
#if 0
        case    CF_CALCOP("Sqrt(A)"):
            CF_CHECK_GTE(bn0, BigInt(0));
            res = sqrt(bn0);
            break;
#endif
        case    CF_CALCOP("Abs(A)"):
            res = abs(bn0);
            break;
        default:
            goto end;
    }

    {
        auto s = res.to_string();
        if ( s == "-0" ) {
            s = "0";
        }
        ret = s;
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
