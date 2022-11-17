#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <iostream>

extern "C" {
    int cryptofuzz_aleo_bignumcalc_fr(
            uint8_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* result);
}
namespace cryptofuzz {
namespace module {

Aleo::Aleo(void) :
    Module("Aleo") { }

std::optional<component::Bignum> Aleo::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "8444461749428370424248824938781546531375899335154063827935233455917409239041" ) {
        return std::nullopt;
    }
    std::optional<component::Bignum> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> bn0_bytes;
    std::optional<std::vector<uint8_t>> bn1_bytes;
    std::array<uint8_t, 32> result;

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("Mul(A,B)"), 2 },
        { CF_CALCOP("InvMod(A,B)"), 3 },
        { CF_CALCOP("Sqr(A)"), 4 },
        { CF_CALCOP("Sqrt(A)"), 5 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    CF_CHECK_NE(bn0_bytes = util::DecToBin(op.bn0.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn1_bytes = util::DecToBin(op.bn1.ToTrimmedString(), 32), std::nullopt);

    {
        const auto res = cryptofuzz_aleo_bignumcalc_fr(
                LUT.at(op.calcOp.Get()),
                bn0_bytes->data(),
                bn1_bytes->data(),
                result.data()
        );

        CF_CHECK_NE(res, -1);
        std::reverse(result.begin(), result.end());
        ret = util::BinToDec(result.data(), 32);
    }

end:
    return ret;
}

bool Aleo::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
