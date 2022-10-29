#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int arkworks_algebra_bignumcalc(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
}
namespace cryptofuzz {
namespace module {

arkworks_algebra::arkworks_algebra(void) :
    Module("arkworks-algebra") { }

namespace arkworks_algebra_detail {
    std::optional<std::array<uint64_t, 4>> ToU64(const component::Bignum& bn, const size_t pos = 0) {
        (void)pos;
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
    const component::Bignum FromU64(std::array<uint64_t, 4> u64) {
        std::reverse(u64.begin(), u64.end());
        std::vector<uint8_t> bin(32);
        u64[0] = __bswap_64(u64[0]);
        u64[1] = __bswap_64(u64[1]);
        u64[2] = __bswap_64(u64[2]);
        u64[3] = __bswap_64(u64[3]);
        memcpy(bin.data(), &u64[0], sizeof(uint64_t));
        memcpy(bin.data() + 8, &u64[1], sizeof(uint64_t));
        memcpy(bin.data() + 16, &u64[2], sizeof(uint64_t));
        memcpy(bin.data() + 24, &u64[3], sizeof(uint64_t));
        return component::Bignum{util::BinToDec(bin)};
    }
}

std::optional<component::Bignum> arkworks_algebra::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return std::nullopt;
    }
    std::optional<component::Bignum> ret = std::nullopt;

    std::optional<std::array<uint64_t, 4>> bn0, bn1, bn2;
    std::array<uint64_t, 4> result;
    CF_CHECK_NE(bn0 = arkworks_algebra_detail::ToU64(op.bn0, 0), std::nullopt);
    CF_CHECK_NE(bn1 = arkworks_algebra_detail::ToU64(op.bn1, 1), std::nullopt);
    CF_CHECK_NE(bn2 = arkworks_algebra_detail::ToU64(op.bn2, 2), std::nullopt);

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("LShift1(A)"), 2 },
        { CF_CALCOP("LShift(A)"), 3 },
        { CF_CALCOP("RShift(A,B)"), 4 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    {
        const auto res = arkworks_algebra_bignumcalc(
                LUT.at(op.calcOp.Get()),
                bn0->data(),
                bn1->data(),
                bn2->data(),
                result.data()
        );

        CF_CHECK_NE(res, -1);

        ret = arkworks_algebra_detail::FromU64(result);
    }

end:
    return ret;
}

bool arkworks_algebra::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
