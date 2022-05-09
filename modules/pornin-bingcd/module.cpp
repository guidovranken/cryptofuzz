#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include <gf25519.h>

namespace cryptofuzz {
namespace module {

Pornin_BinGCD::Pornin_BinGCD(void) :
    Module("Pornin-BinGCD") { }

namespace Pornin_BinGCD_detail {
    std::optional<gf> Load(const component::Bignum& bn) {
        std::array<uint8_t, 32> v;
        const auto a = util::DecToBin(bn.ToTrimmedString(), 32);
        if ( a == std::nullopt ) {
            return std::nullopt;
        }
        memcpy(v.data(), a->data(), 32);
        std::reverse(v.begin(), v.end());
        gf R;
        gf_decode(&R, v.data());
        return R;
    }

    component::Bignum Save(const gf& V) {
        std::array<uint8_t, 32> v;
        CF_NORET(gf_encode(v.data(), &V));
        std::reverse(v.begin(), v.end());
        return util::BinToDec(v.data(), 32);
    }
}

std::optional<component::Bignum> Pornin_BinGCD::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.modulo == std::nullopt ) {
        return ret;
    }

    if ( op.modulo->ToTrimmedString() != "57896044618658097711785492504343953926634992332820282019728792003956564819949" ) {
        return ret;
    }

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            {
                auto A = Pornin_BinGCD_detail::Load(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = Pornin_BinGCD_detail::Load(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                gf R;
                gf_add(&R, &*A, &*B);

                ret = Pornin_BinGCD_detail::Save(R);
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            {
                auto A = Pornin_BinGCD_detail::Load(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = Pornin_BinGCD_detail::Load(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                gf R;
                gf_sub(&R, &*A, &*B);

                ret = Pornin_BinGCD_detail::Save(R);
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            {
                auto A = Pornin_BinGCD_detail::Load(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = Pornin_BinGCD_detail::Load(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                gf R;
                gf_mul(&R, &*A, &*B);

                ret = Pornin_BinGCD_detail::Save(R);
            }
            break;
        case    CF_CALCOP("Sqr(A)"):
            {
                auto A = Pornin_BinGCD_detail::Load(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                gf R;
                gf_sqr(&R, &*A);

                ret = Pornin_BinGCD_detail::Save(R);
            }
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            {
                auto A = Pornin_BinGCD_detail::Load(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                gf R;
                gf_inv(&R, &*A);

                ret = Pornin_BinGCD_detail::Save(R);
            }
            break;
    }

end:
    return ret;
}

bool Pornin_BinGCD::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
