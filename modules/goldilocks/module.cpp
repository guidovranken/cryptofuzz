#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include "src/goldilocks_base_field.cpp"
#include "src/goldilocks_base_field_avx.hpp"

namespace cryptofuzz {
namespace module {

Goldilocks::Goldilocks(void) :
    Module("Goldilocks") { }

namespace Goldilocks_detail {
    static ::Goldilocks::Element Load(
            fuzzing::datasource::Datasource& ds,
            const component::Bignum& bn) {
        bool useFromString = true;

        try {
            useFromString = ds.Get<bool>();
        } catch ( ... ) { }

        if ( useFromString == false ) {
            char* end;
            const auto s = bn.ToTrimmedString();
            const uint64_t v = std::strtoull(s.c_str(), &end, 10);
            if ( std::to_string(v) == s ) {
                return ::Goldilocks::fromU64(v);
            }
            /* Fall through */
        }

        return ::Goldilocks::fromString(bn.ToTrimmedString());
    }

    static __m256i LoadAVX(
            fuzzing::datasource::Datasource& ds,
            const ::Goldilocks::Element& el,
            const size_t index) {
        __m256i ret;
        ::Goldilocks::Element el4[4] = { {0} };

        try {
            for (size_t i = 0; i < 4; i++) {
                if ( i == index ) {
                    continue;
                } else {
                    el4[i] = ::Goldilocks::fromU64(ds.Get<uint64_t>());
                }
            }
        } catch ( ... ) { }

        el4[index] = el;

        ::Goldilocks::load(ret, el4);
        return ret;
    }
}

std::optional<component::Bignum> Goldilocks::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "18446744069414584321" ) {
        return std::nullopt;
    }

    bool avx = false;
    try {
        avx = ds.Get<bool>();
    } catch ( ... ) { }

    size_t avx_index = 0;
    if ( avx == true ) {
        try {
            avx_index = ds.Get<uint8_t>() % 4;
        } catch ( ... ) { }
    }

    const ::Goldilocks::Element a = Goldilocks_detail::Load(ds, op.bn0);
    const ::Goldilocks::Element b = Goldilocks_detail::Load(ds, op.bn1);
    ::Goldilocks::Element res;

    __m256i a_avx, b_avx, res_avx;

    a_avx = Goldilocks_detail::LoadAVX(ds, a, avx_index);
    b_avx = Goldilocks_detail::LoadAVX(ds, b, avx_index);

    bool avx_convert = false;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            if ( avx == false ) {
                res = a + b;
            } else {
                ::Goldilocks::add_avx(res_avx, a_avx, b_avx);
                avx_convert = true;
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            if ( avx == false ) {
                res = a - b;
            } else {
                ::Goldilocks::sub_avx(res_avx, a_avx, b_avx);
                avx_convert = true;
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(b));
            res = a / b;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            if ( avx == false ) {
                res = a * b;
            } else {
                ::Goldilocks::mult_avx(res_avx, a_avx, b_avx);
                avx_convert = true;
            }
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(a));
            res = ::Goldilocks::inv(a);
            break;
        case    CF_CALCOP("Sqr(A)"):
            if ( avx == false ) {
                res = ::Goldilocks::square(a);
            } else {
                ::Goldilocks::square_avx(res_avx, a_avx);
                avx_convert = true;
            }
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

    if ( avx_convert ) {
        ::Goldilocks::Element el4[4];
        ::Goldilocks::store(el4, res_avx);
        res = el4[avx_index];
    }

    {
        bool useToString = true;

        try {
            useToString = ds.Get<bool>();
        } catch ( ... ) { }

        if ( useToString == true ) {
            ret = component::Bignum(::Goldilocks::toString(res));
        } else {
            ret = component::Bignum(std::to_string(::Goldilocks::toU64(res)));
        }
    }

end:
    return ret;
}

bool Goldilocks::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
