#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int rust_uint_bigint_bignumcalc(
            uint64_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t modifier,
            uint8_t* result);
}

namespace cryptofuzz {
namespace module {

rust_uint::rust_uint(void) :
    Module("rust-uint") { }

std::optional<component::Bignum> rust_uint::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.modulo == std::nullopt ) {
        return ret;
    } else if ( op.modulo->ToTrimmedString() != "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return ret;
    }

    uint8_t result[32] = {0};
    std::optional<std::vector<uint8_t>> bn0, bn1, bn2;
    uint8_t modifier = 0;

    CF_CHECK_NE(bn0 = util::DecToBin(op.bn0.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn1 = util::DecToBin(op.bn1.ToTrimmedString(), 32), std::nullopt);

    try {
        modifier = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    {
        const auto res = rust_uint_bigint_bignumcalc(
                op.calcOp.Get(),
                bn0->data(),
                bn1->data(),
                modifier,
                result
        );

        CF_CHECK_EQ(res, 0);

        ret = util::BinToDec(result, sizeof(result));
    }

end:
    return ret;
}

bool rust_uint::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
