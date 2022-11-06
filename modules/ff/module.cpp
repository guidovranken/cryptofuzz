#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int cryptofuzz_ff_bignumcalc(
            uint8_t op,
            uint8_t* bn0_bytes,
            uint8_t* result);
}
namespace cryptofuzz {
namespace module {

ff::ff(void) :
    Module("ff") { }

std::optional<component::Bignum> ff::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        return std::nullopt;
    }
    std::optional<component::Bignum> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> bn0_bytes;
    std::array<uint8_t, 32> result;

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Sqr(A)"), 0 },
        { CF_CALCOP("InvMod(A,B)"), 1 },
        { CF_CALCOP("Sqrt(A)"), 2 },
        { CF_CALCOP("Mul(A,B)"), 3 },
    };

    if ( op.calcOp.Get() == CF_CALCOP("Mul(A,B)") ) {
        CF_CHECK_EQ(op.bn1.ToTrimmedString(), "2");
    }
    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    CF_CHECK_NE(bn0_bytes = util::DecToBin(op.bn0.ToTrimmedString(), 32), std::nullopt);

    {
        const auto res = cryptofuzz_ff_bignumcalc(
                LUT.at(op.calcOp.Get()),
                bn0_bytes->data(),
                result.data()
        );

        CF_CHECK_NE(res, -1);
        ret = util::BinToDec(result.data(), 32);
    }

end:
    return ret;
}

bool ff::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
