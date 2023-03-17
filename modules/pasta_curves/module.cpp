#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <iostream>

extern "C" {
    int cryptofuzz_pasta_curves_bignumcalc_vesta_fq(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint8_t* result);
    int cryptofuzz_pasta_curves_bignumcalc_vesta_fr(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint8_t* result);
}
namespace cryptofuzz {
namespace module {

pasta_curves::pasta_curves(void) :
    Module("pasta_curves") { }
namespace pasta_curves_detail {
    std::optional<std::array<uint64_t, 4>> To4U64(const component::Bignum& bn) {
        std::optional<std::array<uint64_t, 4>> ret = std::nullopt;

        const auto bin = util::DecToBin(bn.ToTrimmedString(), 32);
        CF_CHECK_NE(bin, std::nullopt);

        std::array<uint64_t, 4> arr;
        memcpy(&arr[0], bin->data(), sizeof(uint64_t));
        arr[0] = __bswap_64(arr[0]);
        memcpy(&arr[1], bin->data() + 8, sizeof(uint64_t));
        arr[1] = __bswap_64(arr[1]);
        memcpy(&arr[2], bin->data() + 16, sizeof(uint64_t));
        arr[2] = __bswap_64(arr[2]);
        memcpy(&arr[3], bin->data() + 24, sizeof(uint64_t));
        arr[3] = __bswap_64(arr[3]);

        std::reverse(arr.begin(), arr.end());
        ret = arr;
end:
        return ret;
    }
}

std::optional<component::Bignum> pasta_curves::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.modulo == std::nullopt ) {
        return ret;
    }

    if ( op.modulo->ToTrimmedString() == "28948022309329048855892746252171976963363056481941647379679742748393362948097" ||
        op.modulo->ToTrimmedString() == "28948022309329048855892746252171976963363056481941560715954676764349967630337" ) {
        std::optional<std::array<uint64_t, 4>> bn0, bn1;
        CF_CHECK_NE(bn0 = pasta_curves_detail::To4U64(op.bn0), std::nullopt);
        CF_CHECK_NE(bn1 = pasta_curves_detail::To4U64(op.bn1), std::nullopt);

        static const std::map<uint64_t, uint64_t> LUT = {
            { CF_CALCOP("Add(A,B)"), 0 },
            { CF_CALCOP("Sub(A,B)"), 1 },
            { CF_CALCOP("Mul(A,B)"), 2 },
            { CF_CALCOP("Sqr(A)"), 3 },
            { CF_CALCOP("Sqrt(A)"), 4 },
        };

        CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

        std::array<uint8_t, 32> result;
        if ( op.modulo->ToTrimmedString() == "28948022309329048855892746252171976963363056481941647379679742748393362948097" ) {
            CF_CHECK_EQ(cryptofuzz_pasta_curves_bignumcalc_vesta_fq(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        result.data()), 0);
        } else {
            CF_CHECK_EQ(cryptofuzz_pasta_curves_bignumcalc_vesta_fr(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        result.data()), 0);
        }

        std::reverse(result.begin(), result.end());
        ret = util::BinToDec(result.data(), 32);
    }

end:
    return ret;
}

bool pasta_curves::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
