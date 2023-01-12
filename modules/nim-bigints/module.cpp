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
    auto c = op.bn2.ToTrimmedString();
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
    } else if ( op.calcOp.Is(CF_CALCOP("Div(A,B)")) ) {
        CF_CHECK_FALSE(op.bn1.IsZero());
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_div(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("Mod(A,B)")) ) {
        CF_CHECK_FALSE(op.bn1.IsZero());
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_mod(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("GCD(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_gcd(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("InvMod(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_invmod(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        CF_CHECK_LTE(op.bn0.GetSize(), 500);
        CF_CHECK_LTE(op.bn1.GetSize(), 500);
        CF_CHECK_LTE(op.bn2.GetSize(), 500);
        CF_CHECK_FALSE(op.bn2.IsZero());
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_expmod(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)c.data(), c.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("And(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_and(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("Or(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_or(
                    (uint8_t*)a.data(), a.size(),
                    (uint8_t*)b.data(), b.size(),
                    (uint8_t*)result.data()),
        0);
    } else if ( op.calcOp.Is(CF_CALCOP("Xor(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_nim_bigints_xor(
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
