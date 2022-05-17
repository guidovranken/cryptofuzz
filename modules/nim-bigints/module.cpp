#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    #include <nim_bigints_harness.h>
}

namespace cryptofuzz {
namespace module {

nim_bigints::nim_bigints(void) :
    Module("nim-bigints") {
    CF_NORET(NimMain());
}

std::optional<component::Bignum> nim_bigints::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto a = op.bn0.ToTrimmedString();
    auto b = op.bn1.ToTrimmedString();
    std::array<char, 10240> result;
    memset(result.data(), 0, result.size());

    if ( op.calcOp.Is(CF_CALCOP("Add(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_add(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("Sub(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_sub(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("Mul(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_mul(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else {
        goto end;
    }

    ret = std::string((char*)result.data());

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
