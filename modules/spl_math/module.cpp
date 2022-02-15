#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

using uint128_t = __uint128_t;

extern "C" {
    uint64_t spl_math_sqrt(uint64_t v1, uint64_t v2);
}
namespace cryptofuzz {
namespace module {

spl_math::spl_math(void) :
    Module("spl-math") { }

std::optional<component::Bignum> spl_math::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.calcOp.Get() != CF_CALCOP("Sqrt(A)") ) {
        return std::nullopt;
    }

    auto v_bin = util::DecToBin(op.bn0.ToTrimmedString(), sizeof(uint128_t));
    if ( v_bin == std::nullopt ) {
        return std::nullopt;
    }

    std::reverse(v_bin->begin(), v_bin->end());

    uint64_t v1, v2;
    memcpy(&v1, v_bin->data(), 8);
    memcpy(&v2, v_bin->data() + 8, 8);

    return std::to_string( spl_math_sqrt(v1, v2) );
}

} /* namespace module */
} /* namespace cryptofuzz */
