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

namespace stint_detail {
    std::optional<component::Bignum> OpBignumCalc_U256(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;

        auto a_bytes = util::DecToBin(op.bn0.ToTrimmedString(), 32);
        if ( a_bytes == std::nullopt ) {
            return ret;
        }
        auto b_bytes = util::DecToBin(op.bn1.ToTrimmedString(), 32);
        if ( b_bytes == std::nullopt ) {
            return ret;
        }
        auto c_bytes = util::DecToBin(op.bn2.ToTrimmedString(), 32);
        if ( c_bytes == std::nullopt ) {
            return ret;
        }

        std::array<uint8_t, 32> result;
        memset(result.data(), 0, result.size());

        if ( op.calcOp.Is(CF_CALCOP("Add(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_add_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("Sub(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_sub_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("Mul(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_mul_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_expmod_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        c_bytes->data(), c_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("AddMod(A,B,C)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_addmod_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        c_bytes->data(), c_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("MulMod(A,B,C)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_mulmod_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        c_bytes->data(), c_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("And(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_and_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("Or(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_or_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("Xor(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_xor_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsEq(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_iseq_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("Exp(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_exp_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("LShift1(A)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_lshift1_u256(
                        a_bytes->data(), a_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsOdd(A)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_isodd_u256(
                        a_bytes->data(), a_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsEven(A)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_iseven_u256(
                        a_bytes->data(), a_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsLt(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_islt_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsLte(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_islte_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsGt(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_isgt_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        } else if ( op.calcOp.Is(CF_CALCOP("IsGte(A,B)")) ) {
            CF_CHECK_EQ(
                    cryptofuzz_stint_isgte_u256(
                        a_bytes->data(), a_bytes->size(),
                        b_bytes->data(), b_bytes->size(),
                        result.data()),
                    0);

            ret = util::BinToDec(result.data(), result.size());
        }

end:
        return ret;
    }
}

std::optional<component::Bignum> stint::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo != std::nullopt ) {
        if ( op.modulo->ToTrimmedString() == "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
            return stint_detail::OpBignumCalc_U256(op);
        } else {
            return std::nullopt;
        }
    }

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
        /* Too slow */
        goto end;

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
        /* Prevent timeouts */
        CF_CHECK_LTE(op.bn0.GetSize(), 100);
        CF_CHECK_LTE(op.bn1.GetSize(), 100);
        CF_CHECK_LTE(op.bn2.GetSize(), 100);

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

bool stint::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
