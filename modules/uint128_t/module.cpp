#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>

namespace cryptofuzz {
namespace module {

uint128_t::uint128_t(void) :
    Module("uint128_t") { }

namespace uint128_t_detail {
    __uint128_t Load(const component::Bignum& bn) {
        const boost::multiprecision::uint256_t uboost(bn.ToTrimmedString());
        std::vector<uint8_t> v;
        boost::multiprecision::export_bits(uboost, std::back_inserter(v), 8);
        __uint128_t ret;
        std::reverse(v.begin(), v.end());
        v.resize(sizeof(ret), 0);
        memcpy(&ret, v.data(), v.size());
        return ret;
    }

    component::Bignum Save(const __uint128_t u) {
        std::vector<uint8_t> v(sizeof(u));
        memcpy(v.data(), &u, v.size());
        std::reverse(v.begin(), v.end());
        boost::multiprecision::uint256_t uboost;
        boost::multiprecision::import_bits(uboost, v.data(), v.data() + v.size());
        return component::Bignum{ uboost.str() };
    }
} /* namespace uint128_t_detail */

std::optional<component::Bignum> uint128_t::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.modulo == std::nullopt ) {
        return ret;
    }

    if ( op.modulo->ToTrimmedString() != "340282366920938463463374607431768211456" ) {
        return ret;
    }

    __uint128_t res;

    using namespace uint128_t_detail;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            res = Load(op.bn0) + Load(op.bn1);
            break;
        case    CF_CALCOP("Sub(A,B)"):
            res = Load(op.bn0) - Load(op.bn1);
            break;
        case    CF_CALCOP("Div(A,B)"):
            {
                const auto divisor = Load(op.bn1);
                CF_CHECK_NE(divisor, 0);
                res = Load(op.bn0) / divisor;
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            res = Load(op.bn0) * Load(op.bn1);
            break;
        case    CF_CALCOP("Mod(A,B)"):
            {
                const auto divisor = Load(op.bn1);
                CF_CHECK_NE(divisor, 0);
                res = Load(op.bn0) % divisor;
            }
            break;
        case    CF_CALCOP("Sqr(A)"):
            res = Load(op.bn0) * Load(op.bn0);
            break;
        case    CF_CALCOP("And(A,B)"):
            res = Load(op.bn0) & Load(op.bn1);
            break;
        case    CF_CALCOP("Or(A,B)"):
            res = Load(op.bn0) | Load(op.bn1);
            break;
        case    CF_CALCOP("Xor(A,B)"):
            res = Load(op.bn0) ^ Load(op.bn1);
            break;
        case    CF_CALCOP("Set(A)"):
            res = Load(op.bn0);
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            res = Load(op.bn0) == Load(op.bn1);
            break;
        case    CF_CALCOP("IsGt(A,B)"):
            res = Load(op.bn0) > Load(op.bn1);
            break;
        case    CF_CALCOP("IsGte(A,B)"):
            res = Load(op.bn0) >= Load(op.bn1);
            break;
        case    CF_CALCOP("IsLt(A,B)"):
            res = Load(op.bn0) < Load(op.bn1);
            break;
        case    CF_CALCOP("IsLte(A,B)"):
            res = Load(op.bn0) <= Load(op.bn1);
            break;
        case    CF_CALCOP("IsZero(A)"):
            res = !Load(op.bn0);
            break;
        case    CF_CALCOP("IsOne(A)"):
            res = Load(op.bn0) == 1;
            break;
        case    CF_CALCOP("IsNotZero(A)"):
            res = Load(op.bn0) != 0;
            break;
        default:
            goto end;
    }

    ret = Save(res);

end:
    return ret;
}
        
bool uint128_t::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
