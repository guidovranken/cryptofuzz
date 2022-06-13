#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
    #include "cryptofuzz.h"
}

namespace cryptofuzz {
namespace module {

Geth::Geth(void) :
    Module("Geth") { }
namespace Geth_detail {
    std::vector<uint8_t> Pad(Datasource& ds, const std::vector<uint8_t> v) {
        uint16_t num = 0;

        try {
            num = ds.Get<uint16_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        std::vector<uint8_t> ret(num, 0);
        ret.insert(ret.end(), v.begin(), v.end());
        return ret;
    }

    GoSlice toGoSlice(std::vector<uint8_t>& in) {
        return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
    }

    std::string getResult(void) {
        auto res = Geth_GetResult();
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

    std::optional<Buffer> parseBuffer(const bool mustSucceed = false) {
        const auto res = getJsonResult();
        if ( res == std::nullopt ) {
            if ( mustSucceed == true ) {
                abort();
            }
            return std::nullopt;
        }
        return Buffer(*res);
    }
    std::optional<component::Bignum> parseBignum(const bool mustSucceed = false) {
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
        return component::Bignum{util::BinToDec(data)};
    }
}
std::optional<component::Digest> Geth::OpDigest(operation::Digest& op) {
    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        auto input = op.cleartext.Get();
        Geth_Call(0x02, Geth_detail::toGoSlice(input), 0);
    } else if ( op.digestType.Is(CF_DIGEST("RIPEMD160")) ) {
        auto input = op.cleartext.Get();
        Geth_Call(0x03, Geth_detail::toGoSlice(input), 0);
    } else {
        return std::nullopt;
    }

    auto ret = *Geth_detail::parseBuffer(true);
    if ( op.digestType.Is(CF_DIGEST("RIPEMD160")) ) {
        const auto v = ret.Get();
        CF_ASSERT(v.size() == 32, "RIPEMD160 result is not 32 bytes");
        ret = Buffer(std::vector<uint8_t>(v.data() + 12, v.data() + 32));
    }
    return ret;
}

std::optional<component::Bignum> Geth::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( !op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        return ret;
    }
    if ( op.bn0.ToTrimmedString() == "0" ) {
        return ret;
    }
    if ( op.bn1.ToTrimmedString() == "0" ) {
        return ret;
    }
    if ( op.bn2.ToTrimmedString() == "0" ) {
        return ret;
    }

    std::vector<uint8_t> input;

    const auto b = Geth_detail::Pad(ds, *op.bn0.ToBin());
    const auto bl = util::DecToBin(std::to_string(b.size()), 32);
    const auto e = Geth_detail::Pad(ds, *op.bn1.ToBin());
    const auto el = util::DecToBin(std::to_string(e.size()), 32);
    const auto m = Geth_detail::Pad(ds, *op.bn2.ToBin());
    const auto ml = util::DecToBin(std::to_string(m.size()), 32);
    input.insert(input.end(), bl->begin(), bl->end());
    input.insert(input.end(), el->begin(), el->end());
    input.insert(input.end(), ml->begin(), ml->end());
    input.insert(input.end(), b.begin(), b.end());
    input.insert(input.end(), e.begin(), e.end());
    input.insert(input.end(), m.begin(), m.end());

    CF_NORET(
            Geth_Call(0x05, Geth_detail::toGoSlice(input), 0)
    );

    ret = Geth_detail::parseBignum(true);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
