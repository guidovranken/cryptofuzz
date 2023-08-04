#include "module.h"
#include <cryptofuzz/util.h>

extern "C" {
    void cryptofuzz_aurora_engine_modexp(
            const uint8_t* base_bytes, const uint64_t base_size,
            const uint8_t* exp_bytes, const uint64_t exp_size,
            const uint8_t* mod_bytes, const uint64_t mod_size,
            uint32_t loops,
            uint8_t* result);
}

namespace cryptofuzz {
namespace module {

aurora_engine_modexp::aurora_engine_modexp(void) :
    Module("aurora-engine-modexp") { }

namespace aurora_engine_modexp_detail {
    std::vector<uint8_t> Pad(Datasource& ds, std::vector<uint8_t> v) {
        if ( v == std::vector<uint8_t>(v.size(), 0) ) {
            v = {};
        }

        uint16_t num = 0;

        try {
            num = ds.Get<uint32_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        num &= 0xFFFFFF;

        std::vector<uint8_t> ret(num, 0);
        ret.insert(ret.end(), v.begin(), v.end());
        return ret;
    }
}

std::optional<component::Bignum> aurora_engine_modexp::OpBignumCalc(operation::BignumCalc& op) {
    if ( !op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Bignum> ret = std::nullopt;
    uint32_t loops = 1;
    std::array<uint8_t, 4000> result;
    memset(result.data(), 0, result.size());

    const auto base = aurora_engine_modexp_detail::Pad(
            ds, *util::DecToBin(op.bn0.ToTrimmedString()));
    const auto exp = aurora_engine_modexp_detail::Pad(
            ds, *util::DecToBin(op.bn1.ToTrimmedString()));
    const auto mod = aurora_engine_modexp_detail::Pad(
            ds, *util::DecToBin(op.bn2.ToTrimmedString()));

#if 0
    loops = 30000000 / util::Ethereum_ModExp::Gas(
        util::Ethereum_ModExp::ToInput(op.bn0, op.bn1, op.bn2),
        true
    );
#endif

    cryptofuzz_aurora_engine_modexp(
            base.data(), base.size(),
            exp.data(), exp.size(),
            mod.data(), mod.size(),
            loops,
            result.data());

    std::reverse(result.begin(), result.end());

    {
        const auto res = util::BinToDec(result.data(), result.size());
        if ( op.bn2.IsZero() ) {
            CF_ASSERT(res == "0", "ModExp with modulus is not 0");
        } else {
            ret = util::BinToDec(result.data(), result.size());
        }
    }

    return ret;
}
} /* namespace module */
} /* namespace cryptofuzz */
