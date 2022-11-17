#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <iostream>

extern "C" {
    int cryptofuzz_aleo_bignumcalc_fq(
            uint8_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* result);
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

    size_t size = 0;
    if ( op.modulo->ToTrimmedString() == "8444461749428370424248824938781546531375899335154063827935233455917409239041" ) {
        size = 32;
    } else if ( op.modulo->ToTrimmedString() == "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177" ) {
        size = 48;
    } else {
        return std::nullopt;
    }
    std::optional<component::Bignum> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> bn0_bytes;
    std::optional<std::vector<uint8_t>> bn1_bytes;
    std::array<uint8_t, 32> result_fr;
    std::array<uint8_t, 48> result_fq;

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("Mul(A,B)"), 2 },
        { CF_CALCOP("InvMod(A,B)"), 3 },
        { CF_CALCOP("Sqr(A)"), 4 },
        { CF_CALCOP("Sqrt(A)"), 5 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    CF_CHECK_NE(bn0_bytes = util::DecToBin(op.bn0.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(bn1_bytes = util::DecToBin(op.bn1.ToTrimmedString(), size), std::nullopt);

    {
        if ( size == 32 ) {
            const auto res = cryptofuzz_aleo_bignumcalc_fr(
                    LUT.at(op.calcOp.Get()),
                    bn0_bytes->data(),
                    bn1_bytes->data(),
                    result_fr.data()
                    );

            CF_CHECK_NE(res, -1);
            std::reverse(result_fr.begin(), result_fr.end());
            ret = util::BinToDec(result_fr.data(), 32);
        } else if ( size == 48 ) {
            const auto res = cryptofuzz_aleo_bignumcalc_fq(
                    LUT.at(op.calcOp.Get()),
                    bn0_bytes->data(),
                    bn1_bytes->data(),
                    result_fq.data()
                    );

            CF_CHECK_NE(res, -1);
            std::reverse(result_fq.begin(), result_fq.end());
            ret = util::BinToDec(result_fq.data(), 48);
        } else {
            CF_UNREACHABLE();
        }
    }

end:
    return ret;
}

bool Aleo::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
