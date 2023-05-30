#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include "src/goldilocks_base_field.cpp"
#include "src/goldilocks_base_field_avx.hpp"
#include "src/goldilocks_base_field_avx512.hpp"

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

        ::Goldilocks::load_avx(ret, el4);
        return ret;
    }

#if defined(__AVX512__)
    static __m512i LoadAVX512(
            fuzzing::datasource::Datasource& ds,
            const ::Goldilocks::Element& el,
            const size_t index) {
        __m512i ret;
        ::Goldilocks::Element el8[8] = { {0} };

        try {
            for (size_t i = 0; i < 8; i++) {
                if ( i == index ) {
                    continue;
                } else {
                    el8[i] = ::Goldilocks::fromU64(ds.Get<uint64_t>());
                }
            }
        } catch ( ... ) { }

        el8[index] = el;

        ::Goldilocks::load_avx512(ret, el8);
        return ret;
    }
#endif
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

    uint8_t avx = 0;
    try {
#if defined(__AVX512__)
        avx = ds.Get<uint8_t>() % 3;
#else
        avx = ds.Get<uint8_t>() % 2;
#endif
    } catch ( ... ) { }

    size_t avx_index = 0;
    if ( avx == 1 ) {
        try {
            avx_index = ds.Get<uint8_t>() % 4;
        } catch ( ... ) { }
    } else if ( avx == 2 ) {
        try {
            avx_index = ds.Get<uint8_t>() % 8;
        } catch ( ... ) { }
    }

    const ::Goldilocks::Element a = Goldilocks_detail::Load(ds, op.bn0);
    const ::Goldilocks::Element b = Goldilocks_detail::Load(ds, op.bn1);
    ::Goldilocks::Element res;

    __m256i a_avx, b_avx, res_avx;
#if defined(__AVX512__)
    __m512i a_avx512, b_avx512, res_avx512;
#endif

    a_avx = Goldilocks_detail::LoadAVX(ds, a, avx_index);
    b_avx = Goldilocks_detail::LoadAVX(ds, b, avx_index);
#if defined(__AVX512__)
    a_avx512 = Goldilocks_detail::LoadAVX512(ds, a, avx_index);
    b_avx512 = Goldilocks_detail::LoadAVX512(ds, b, avx_index);
#endif

    uint8_t avx_convert = 0;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            if ( avx == 0 ) {
                res = a + b;
            } else if ( avx == 1 ) {
                ::Goldilocks::add_avx(res_avx, a_avx, b_avx);
                avx_convert = 1;
#if defined(__AVX512__)
            } else if ( avx == 2 ) {
                ::Goldilocks::add_avx512(res_avx512, a_avx512, b_avx512);
                avx_convert = 2;
#endif
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            if ( avx == 0 ) {
                res = a - b;
            } else if ( avx == 1 ) {
                ::Goldilocks::sub_avx(res_avx, a_avx, b_avx);
                avx_convert = 1;
#if defined(__AVX512__)
            } else if ( avx == 2 ) {
                ::Goldilocks::sub_avx512(res_avx512, a_avx512, b_avx512);
                avx_convert = 2;
#endif
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(b));
            res = a / b;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            if ( avx == 0 ) {
                res = a * b;
            } else if ( avx == 1 ) {
                ::Goldilocks::mult_avx(res_avx, a_avx, b_avx);
                avx_convert = 1;
#if defined(__AVX512__)
            } else if ( avx == 2 ) {
                ::Goldilocks::mult_avx512(res_avx512, a_avx512, b_avx512);
                avx_convert = 2;
#endif
            }
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            CF_CHECK_FALSE(::Goldilocks::isZero(a));
            res = ::Goldilocks::inv(a);
            break;
        case    CF_CALCOP("Sqr(A)"):
            if ( avx == 0 ) {
                res = ::Goldilocks::square(a);
            } else {
                ::Goldilocks::square_avx(res_avx, a_avx);
                avx_convert = 1;
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

    if ( avx_convert == 1 ) {
        ::Goldilocks::Element el4[4];
        ::Goldilocks::store_avx(el4, res_avx);
        res = el4[avx_index];
#if defined(__AVX512__)
    } else if ( avx_convert == 2 ) {
        ::Goldilocks::Element el8[8];
        ::Goldilocks::store_avx512(el8, res_avx512);
        res = el8[avx_index];
#endif
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
