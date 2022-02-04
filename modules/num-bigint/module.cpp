#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int rust_num_bigint_bignumcalc(
            uint64_t op,
            const bool bn0_sign, uint8_t* bn0_bytes, const size_t bn0_size,
            const bool bn1_sign, uint8_t* bn1_bytes, const size_t bn1_size,
            const bool bn2_sign, uint8_t* bn2_bytes, const size_t bn2_size,
            uint8_t* result);
}
namespace cryptofuzz {
namespace module {

num_bigint::num_bigint(void) :
    Module("num-bigint") { }

std::optional<component::Bignum> num_bigint::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto bn0_ = op.bn0;
    bn0_.ToPositive();
    auto bn0 = util::DecToBin(bn0_.ToTrimmedString());

    auto bn1_ = op.bn1;
    bn1_.ToPositive();
    auto bn1 = util::DecToBin(bn1_.ToTrimmedString());

    auto bn2_ = op.bn2;
    bn2_.ToPositive();
    auto bn2 = util::DecToBin(bn2_.ToTrimmedString());

    std::array<uint8_t, 4000> result;
    memset(result.data(), 0, result.size());

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("Mul(A,B)"), 2 },
        { CF_CALCOP("Div(A,B)"), 3 },
        { CF_CALCOP("Mod(A,B)"), 4 },
        { CF_CALCOP("ExpMod(A,B,C)"), 5 },
        { CF_CALCOP("Sqrt(A)"), 6 },
        { CF_CALCOP("LShift1(A)"), 7 },
        { CF_CALCOP("And(A,B)"), 8 },
        { CF_CALCOP("Or(A,B)"), 9 },
        { CF_CALCOP("Xor(A,B)"), 10 },
        { CF_CALCOP("GCD(A,B)"), 11 },
        { CF_CALCOP("LCM(A,B)"), 12 },
        { CF_CALCOP("IsEven(A)"), 13 },
        { CF_CALCOP("IsOdd(A)"), 14 },
        { CF_CALCOP("IsLt(A,B)"), 15 },
        { CF_CALCOP("IsLte(A,B)"), 16 },
        { CF_CALCOP("IsEq(A,B)"), 17 },
        { CF_CALCOP("IsGt(A,B)"), 18 },
        { CF_CALCOP("IsGte(A,B)"), 19 },
        { CF_CALCOP("NumBits(A)"), 20 },
        { CF_CALCOP("Exp(A,B)"), 21 },
        { CF_CALCOP("RShift(A,B)"), 22 },
        { CF_CALCOP("ClearBit(A,B)"), 23 },
        { CF_CALCOP("SetBit(A,B)"), 24 },
        { CF_CALCOP("Min(A,B)"), 25 },
        { CF_CALCOP("Max(A,B)"), 26 },
        { CF_CALCOP("NumLSZeroBits(A)"), 27 },
        { CF_CALCOP("Bit(A,B)"), 28 },
        { CF_CALCOP("InvMod(A,B)"), 29 },
        { CF_CALCOP("IsZero(A)"), 30 },
        { CF_CALCOP("IsOne(A)"), 31 },
        { CF_CALCOP("Set(A)"), 32 },
        { CF_CALCOP("Cbrt(A)"), 33 },
        { CF_CALCOP("Abs(A)"), 34 },
        { CF_CALCOP("IsNeg(A)"), 35 },
        { CF_CALCOP("Nthrt(A,B)"), 36 },
        { CF_CALCOP("ExtGCD_X(A,B)"), 37 },
        { CF_CALCOP("ExtGCD_Y(A,B)"), 38 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    {
        const auto res = rust_num_bigint_bignumcalc(
                LUT.at(op.calcOp.Get()),
                !op.bn0.IsNegative(), bn0->data(), bn0->size(),
                !op.bn1.IsNegative(), bn1->data(), bn1->size(),
                !op.bn2.IsNegative(), bn2->data(), bn2->size(),
                result.data()
        );

        CF_CHECK_NE(res, -1);

        std::reverse(result.begin(), result.end());

        const auto str = util::BinToDec(result.data(), result.size());

        if ( res == 0 ) {
            ret = str;
        } else {
            ret = std::string("-") + str;
        }
    }


end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
