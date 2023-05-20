#include "module.h"
#include <cryptofuzz/util.h>

extern "C" {
    void cryptofuzz_aurora_engine_modexp(
            const uint8_t* base_bytes, const uint64_t base_size,
            const uint8_t* exp_bytes, const uint64_t exp_size,
            const uint8_t* mod_bytes, const uint64_t mod_size,
            uint8_t* result);
}

namespace cryptofuzz {
namespace module {

aurora_engine_modexp::aurora_engine_modexp(void) :
    Module("aurora-engine-modexp") { }

std::optional<component::Bignum> aurora_engine_modexp::OpBignumCalc(operation::BignumCalc& op) {
    if ( !op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        return std::nullopt;
    }
    if ( op.bn2.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    std::optional<component::Bignum> ret = std::nullopt;
    std::array<uint8_t, 4000> result;
    memset(result.data(), 0, result.size());

    std::vector<uint8_t> base = *util::DecToBin(op.bn0.ToTrimmedString());
    std::vector<uint8_t> exp = *util::DecToBin(op.bn1.ToTrimmedString());
    std::vector<uint8_t> mod = *util::DecToBin(op.bn2.ToTrimmedString());

    cryptofuzz_aurora_engine_modexp(
            base.data(), base.size(),
            exp.data(), exp.size(),
            mod.data(), mod.size(),
            result.data());

    std::reverse(result.begin(), result.end());

    ret = util::BinToDec(result.data(), result.size());

    return ret;
}
} /* namespace module */
} /* namespace cryptofuzz */
