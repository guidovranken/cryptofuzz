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
    std::optional<component::G1> parseG1(
            const size_t element_size,
            const bool mustSucceed = false) {
        const auto res = getJsonResult();
        if ( res == std::nullopt ) {
            if ( mustSucceed == true ) {
                abort();
            }
            return std::nullopt;
        }
        const auto s = res->get<std::string>();
        if ( s.size() == 0 ) {
            if ( mustSucceed == true ) {
                abort();
            }
            return std::nullopt;
        }
        std::vector<uint8_t> data;
        boost::algorithm::unhex(s, std::back_inserter(data));
        CF_ASSERT(data.size() == (element_size * 2), "Unexpected return data size");

        return component::G1{
            util::BinToDec(std::vector<uint8_t>(
                        data.data(),
                        data.data() + element_size)),
            util::BinToDec(std::vector<uint8_t>(
                        data.data() + element_size,
                        data.data() + (element_size * 2))),
        };
    }

    std::optional<bool> parseBool(const bool mustSucceed = false) {
        const auto res = getJsonResult();
        if ( res == std::nullopt ) {
            if ( mustSucceed == true ) {
                abort();
            }
            return false;
        }

        const auto s = res->get<std::string>();
        std::vector<uint8_t> data;
        boost::algorithm::unhex(s, std::back_inserter(data));

        static const std::vector<uint8_t> zero{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        static const std::vector<uint8_t> one{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };

        if ( data == zero ) {
            return false;
        } else if ( data == one ) {
            return true;
        } else {
            CF_ASSERT(0, "BN pairing return data is not 0 or 1");
        }
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

std::optional<component::G1> Geth::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    size_t element_size = 0;
    uint8_t precompile = 0;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        element_size = 32;
        precompile = 0x06;
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
        /* https://eips.ethereum.org/EIPS/eip-2537
         *
         * Base field element (Fp) is encoded as 64 bytes by performing BigEndian encoding
         * of the corresponding (unsigned) integer (top 16 bytes are always zeroes).
         */
        element_size = 64;
        precompile = 0x0A;
    } else {
        return ret;
    }

    std::vector<uint8_t> input;
    std::optional<std::vector<uint8_t>> a_x, a_y, b_x, b_y;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        CF_CHECK_FALSE(op.a.first.ToTrimmedString() == "1" &&
                op.a.second.ToTrimmedString() == "2");
        CF_CHECK_FALSE(op.b.first.ToTrimmedString() == "1" &&
                op.b.second.ToTrimmedString() == "2");
    }

    CF_CHECK_NE(a_x = op.a.first.ToBin(element_size), std::nullopt);
    CF_CHECK_NE(a_y = op.a.second.ToBin(element_size), std::nullopt);
    CF_CHECK_NE(b_x = op.b.first.ToBin(element_size), std::nullopt);
    CF_CHECK_NE(b_y = op.b.second.ToBin(element_size), std::nullopt);

    input.insert(input.end(), a_x->begin(), a_x->end());
    input.insert(input.end(), a_y->begin(), a_y->end());
    input.insert(input.end(), b_x->begin(), b_x->end());
    input.insert(input.end(), b_y->begin(), b_y->end());

    CF_NORET(
            Geth_Call(precompile, Geth_detail::toGoSlice(input), 0)
    );

    ret = Geth_detail::parseG1(element_size, false);

end:
    return ret;
}

std::optional<component::G1> Geth::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    size_t element_size = 0;
    uint8_t precompile = 0;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        element_size = 32;
        precompile = 0x07;
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
        element_size = 64;
        precompile = 0x0B;
    } else {
        return ret;
    }

    std::vector<uint8_t> input;
    std::optional<std::vector<uint8_t>> a_x, a_y, b;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        CF_CHECK_FALSE(op.a.first.ToTrimmedString() == "1" &&
                op.a.second.ToTrimmedString() == "2");
    }

    CF_CHECK_NE(a_x = op.a.first.ToBin(element_size), std::nullopt);
    CF_CHECK_NE(a_y = op.a.second.ToBin(element_size), std::nullopt);
    CF_CHECK_NE(b = op.b.ToBin(32), std::nullopt);

    input.insert(input.end(), a_x->begin(), a_x->end());
    input.insert(input.end(), a_y->begin(), a_y->end());
    input.insert(input.end(), b->begin(), b->end());

    CF_NORET(
            Geth_Call(precompile, Geth_detail::toGoSlice(input), 0)
    );

    ret = Geth_detail::parseG1(element_size, false);

end:
    return ret;
}

std::optional<bool> Geth::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;

    std::vector<uint8_t> input;

    for (const auto& cur : op.bf.c) {
        std::optional<std::vector<uint8_t>> a_x, a_y, b_v, b_w, b_x, b_y;
        CF_CHECK_NE(a_x = cur.g1.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(a_y = cur.g1.second.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_v = cur.g2.first.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_w = cur.g2.first.second.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_x = cur.g2.second.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_y = cur.g2.second.second.ToBin(32), std::nullopt);

        input.insert(input.end(), a_x->begin(), a_x->end());
        input.insert(input.end(), a_y->begin(), a_y->end());
        input.insert(input.end(), b_x->begin(), b_x->end());
        input.insert(input.end(), b_v->begin(), b_v->end());
        input.insert(input.end(), b_y->begin(), b_y->end());
        input.insert(input.end(), b_w->begin(), b_w->end());
    }

    CF_NORET(
            Geth_Call(0x08, Geth_detail::toGoSlice(input), 0)
    );

    ret = Geth_detail::parseBool(false);

end:
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
