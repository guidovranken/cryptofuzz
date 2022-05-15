#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    #include <stint_harness.h>
}

namespace cryptofuzz {
namespace module {

stint::stint(void) :
    Module("stint") { }

std::optional<component::Bignum> stint::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto a_bytes = util::DecToBin(op.bn0.ToTrimmedString(), 4096);
    if ( a_bytes == std::nullopt ) {
        return ret;
    }
    auto b_bytes = util::DecToBin(op.bn1.ToTrimmedString(), 4096);
    if ( b_bytes == std::nullopt ) {
        return ret;
    }
    auto c_bytes = util::DecToBin(op.bn2.ToTrimmedString(), 4096);
    if ( c_bytes == std::nullopt ) {
        return ret;
    }

    std::array<uint8_t, 4096> result;
    memset(result.data(), 0, result.size());

    if ( op.calcOp.Is(CF_CALCOP("Add(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_add(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("Sub(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_sub(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("Mul(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_mul(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_expmod(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    c_bytes->data(), c_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("AddMod(A,B,C)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_addmod(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    c_bytes->data(), c_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("MulMod(A,B,C)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_mulmod(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    c_bytes->data(), c_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("And(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_and(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("Or(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_or(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("Xor(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_xor(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsEq(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_iseq(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("Exp(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_exp(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("LShift1(A)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_lshift1(
                    a_bytes->data(), a_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsOdd(A)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_isodd(
                    a_bytes->data(), a_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsEven(A)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_iseven(
                    a_bytes->data(), a_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsLt(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_islt(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsLte(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_islte(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsGt(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_isgt(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    } else if ( op.calcOp.Is(CF_CALCOP("IsGte(A,B)")) ) {
        CF_CHECK_EQ(
                cryptofuzz_stint_isgte(
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()),
        0);

        ret = util::BinToDec(result.data(), result.size());
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
