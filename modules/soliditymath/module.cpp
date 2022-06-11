#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <map>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
    #include "cryptofuzz.h"
}

struct Contract {
    std::string name;
    std::map<uint64_t, std::pair<std::string, std::array<uint8_t, 4>>> hashes;
    std::vector<uint8_t> bytecode;
};

#include "contracts.h"

namespace cryptofuzz {
namespace module {

namespace SolidityMath_detail {
    std::map<uint64_t, std::vector<const Contract*>> calcop2contract;

    GoSlice toGoSlice(std::vector<uint8_t>& in) {
        return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
    }
    uint64_t getGas(Datasource& ds) {
        uint64_t ret = 0;

        try {
            ret = ds.Get<uint64_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        return ret;
    }

    bool append(std::vector<uint8_t>& out, const component::Bignum& val) {
        auto b = val.ToBin(32);
        CF_CHECK_NE(b, std::nullopt);

        out.insert(out.end(), b->begin(), b->end());

        return true;

end:
        return false;
    }

    void append(std::vector<uint8_t>& out, const std::array<uint8_t, 4>& fourbyte) {
        std::array<uint8_t, 20> fourbyte_ = {};

        memcpy(fourbyte_.data(), fourbyte.data(), fourbyte.size());

        out.insert(out.end(), fourbyte.begin(), fourbyte.end());
    }

    std::string getResult(void) {
        auto res = SolidityMath_GetResult();
        std::string ret(res);
        free(res);
        return ret;
    }

    std::optional<nlohmann::json> getJsonResult(void) {
        const auto res = getResult();
        if ( res.empty() ) {
            return std::nullopt;
        }

        try {
            return nlohmann::json::parse(getResult());
        } catch ( std::exception e ) {
            /* Must always parse correctly non-empty strings */
            abort();
        }
    }

    template <size_t Size>
    std::optional<component::Bignum> parseInt(const bool mustSucceed = false) {
        const auto res = getJsonResult();
        if ( res == std::nullopt ) {
            if ( mustSucceed == true ) {
                abort();
            }
            return std::nullopt;
        }
        const auto s = res->get<std::string>();
        std::vector<uint8_t> data;
        boost::algorithm::unhex(s, std::back_inserter(data));

        CF_ASSERT(data.size() == Size, "return value is invalid size");

        return component::Bignum{util::BinToDec(data)};
    }
}

SolidityMath::SolidityMath(void) :
    Module("SolidityMath") {
    for (size_t i = 0; i < contracts.size(); i++) {
        for (const auto& h : contracts[i].hashes) {
            SolidityMath_detail::calcop2contract[h.first].push_back(&contracts[i]);
        }
    }
}

std::optional<component::Bignum> SolidityMath::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::vector<uint8_t> calldata;
    const auto calcop = op.calcOp.Get();
    const auto& contracts = SolidityMath_detail::calcop2contract[calcop];
    const size_t amount = contracts.size();

    if ( amount == 0 ) {
        return ret;
    }

    uint8_t which = 0;

    try {
        which = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    const auto& contract = contracts[which % amount];

    const auto hash = contract->hashes.at(calcop).second;
    SolidityMath_detail::append(calldata, hash);

    {
        if ( calcop == CF_CALCOP("MulDiv(A,B,C)") ) {
            if ( op.bn0.ToTrimmedString() == "0" || op.bn1.ToTrimmedString() == "0" ) {
                goto end;
            }
        }

        if ( calcop == CF_CALCOP("InvMod(A,B)") ) {
            CF_CHECK_EQ(op.bn1.ToTrimmedString(), "115792089237316195423570985008687907853269984665640564039457584007913129639936");
        }
        const auto numParams = repository::CalcOpToNumParams(calcop);

        if ( numParams > 0 ) {
            CF_CHECK_TRUE(SolidityMath_detail::append(calldata, op.bn0));
        }
        if ( numParams > 1 ) {
            if ( calcop == CF_CALCOP("InvMod(A,B)") ) {
                CF_CHECK_TRUE(SolidityMath_detail::append(calldata, op.bn0));
            } else {
                CF_CHECK_TRUE(SolidityMath_detail::append(calldata, op.bn1));
            }
        }
        if ( numParams > 2 ) {
            CF_CHECK_TRUE(SolidityMath_detail::append(calldata, op.bn2));
        }
        if ( numParams > 3 ) {
            CF_CHECK_TRUE(SolidityMath_detail::append(calldata, op.bn3));
        }

        auto bytecode = contract->bytecode;
        const auto gas = SolidityMath_detail::getGas(ds);

        SolidityMath_Call(
                SolidityMath_detail::toGoSlice(bytecode),
                SolidityMath_detail::toGoSlice(calldata),
                gas);

        {
            static const std::array<uint8_t, 4> mul512{0x73, 0xd0, 0xb5, 0x12};

            if ( hash == mul512 ) {
                ret = SolidityMath_detail::parseInt<64>(gas ? false : true);
            } else {
                ret = SolidityMath_detail::parseInt<32>();
            }
        }
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
