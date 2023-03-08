#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include "src/goldilocks_base_field.cpp"

namespace cryptofuzz {
namespace module {

Goldilocks::Goldilocks(void) :
    Module("Goldilocks") { }

std::optional<component::Bignum> Goldilocks::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "18446744069414584321" ) {
        return std::nullopt;
    }

    const ::Goldilocks::Element a = ::Goldilocks::fromString(op.bn0.ToTrimmedString());
    const ::Goldilocks::Element b = ::Goldilocks::fromString(op.bn1.ToTrimmedString());
    ::Goldilocks::Element res;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            res = a + b;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            res = a - b;
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(b));
            res = a / b;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            res = a * b;
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(a));
            res = ::Goldilocks::inv(a);
            break;
        case    CF_CALCOP("Sqr(A)"):
            res = ::Goldilocks::square(a);
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            res = a == b ? ::Goldilocks::one() : ::Goldilocks::zero();
            break;
        case    CF_CALCOP("IsZero(A)"):
            res = ::Goldilocks::isZero(a) ? ::Goldilocks::one() : ::Goldilocks::zero();
            break;
        default:
            goto end;
    }

    ret = component::Bignum(::Goldilocks::toString(res));

end:
    return ret;
}

bool Goldilocks::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
