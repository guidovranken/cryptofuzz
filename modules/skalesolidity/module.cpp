#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/lexical_cast.hpp>

extern "C" {
    #include "cryptofuzz.h"
}

namespace cryptofuzz {
namespace module {

SkaleSolidity::SkaleSolidity(void) :
    Module("SkaleSolidity") {
}

namespace SkaleSolidity_detail {
std::string getResult(void) {
    auto res = SkaleSolidity_GetResult();
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

GoSlice toGoSlice(std::vector<uint8_t>& in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
}

bool append(std::vector<uint8_t>& out, const component::Bignum& val) {
    auto b = val.ToBin(32);
    CF_CHECK_NE(b, std::nullopt);

    out.insert(out.end(), b->begin(), b->end());

    return true;

end:
    return false;
}

/* BignumPair matches both Fp2 and G1 */
bool append(std::vector<uint8_t>& out, const component::BignumPair& fp2) {
    CF_CHECK_TRUE(append(out, fp2.first));
    CF_CHECK_TRUE(append(out, fp2.second));

    return true;

end:
    return false;
}

bool append(std::vector<uint8_t>& out, const component::G2& g2) {
    CF_CHECK_TRUE(append(out, g2.first.first));
    CF_CHECK_TRUE(append(out, g2.second.first));
    CF_CHECK_TRUE(append(out, g2.first.second));
    CF_CHECK_TRUE(append(out, g2.second.second));

    return true;

end:
    return false;
}

void append(std::vector<uint8_t>& out, const std::array<uint8_t, 4>& fourbyte) {
    std::array<uint8_t, 20> fourbyte_ = {};

    memcpy(fourbyte_.data(), fourbyte.data(), fourbyte.size());

    out.insert(out.end(), fourbyte.begin(), fourbyte.end());
}

std::optional<bool> parseBool(void) {
    const auto res = getJsonResult();
    if ( res == std::nullopt ) {
        return std::nullopt;
    }

    const auto s = res->get<std::string>();
    std::vector<uint8_t> data;
    boost::algorithm::unhex(s, std::back_inserter(data));

    CF_ASSERT(data.size() == 32, "return value of type 'bool' is not 32 bytes");

    const auto bn_str = util::BinToDec(data);

    CF_ASSERT(bn_str == "0" || bn_str == "1", "return value of type 'bool' is not 0 or 1");

    return static_cast<bool>(data[31]);
}

std::optional<component::Bignum> parseU256(const bool mustSucceed = false) {
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

    CF_ASSERT(data.size() == 32, "return value of type 'uint' is not 32 bytes");

    return component::Bignum{util::BinToDec(data)};
}

std::optional<component::Fp2> parseFp2(const bool mustSucceed = false) {
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

    CF_ASSERT(data.size() == 64, "return value of type 'Fp2' is not 64 bytes");

    return component::Fp2{
        util::BinToDec(std::vector<uint8_t>(data.data(), data.data() + 32)),
        util::BinToDec(std::vector<uint8_t>(data.data() + 32, data.data() + 64))
    };
}

std::optional<component::Fp2> parseBoolAsFp2(const bool mustSucceed = false) {
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

    CF_ASSERT(data.size() == 32, "return value of type 'bool' is not 32 bytes");

    return component::Fp2{
        util::BinToDec(std::vector<uint8_t>(data.data(), data.data() + 32)),
        "0"
    };
}

std::optional<component::G2> parseG2(void) {
    const auto res = getJsonResult();
    if ( res == std::nullopt ) {
        return std::nullopt;
    }

    const auto s = res->get<std::string>();
    std::vector<uint8_t> data;
    boost::algorithm::unhex(s, std::back_inserter(data));

    CF_ASSERT(data.size() == 128, "return value of type 'G2' is not 128 bytes");

    const std::vector<uint8_t> x{data.data(), data.data() + 32};
    const std::vector<uint8_t> v{data.data() + 32, data.data() + 64};
    const std::vector<uint8_t> y{data.data() + 64, data.data() + 96};
    const std::vector<uint8_t> w{data.data() + 96, data.data() + 128};

    return component::G2{
        util::BinToDec(x), util::BinToDec(y),
        util::BinToDec(v), util::BinToDec(w)
    };
}

uint64_t getGas(Datasource& ds) {
    uint64_t ret = 0;
    try {
        ret = ds.Get<uint64_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    return ret;
}

}

std::optional<bool> SkaleSolidity::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
        return std::nullopt;
    }

    std::vector<uint8_t> calldata;
    SkaleSolidity_detail::append(calldata, {0x67, 0xA1, 0xA5, 0x2C});

    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.g1));

    SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

    return SkaleSolidity_detail::parseBool();

end:
    return std::nullopt;
}

std::optional<bool> SkaleSolidity::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
        return std::nullopt;
    }

    std::vector<uint8_t> calldata;
    SkaleSolidity_detail::append(calldata, {0x3c, 0xcd, 0x2c, 0x0c});

    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.g2));

    SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

    return SkaleSolidity_detail::parseBool();

end:
    return std::nullopt;
}

std::optional<bool> SkaleSolidity::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
        return std::nullopt;
    }

    std::vector<uint8_t> calldata;

    SkaleSolidity_detail::append(calldata, {0x13, 0x6b, 0x56, 0x3a});

    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.a));
    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.b));

    SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

    return SkaleSolidity_detail::parseBool();

end:
    return std::nullopt;
}

namespace SkaleSolidity_detail {
    static std::optional<component::G2> OpBLS_G2_Double(operation::BLS_G2_Add& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
            return std::nullopt;
        }

        std::vector<uint8_t> calldata;

        SkaleSolidity_detail::append(calldata, {0x84, 0x52, 0x85, 0xa7});

        CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.a));

        SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

        return SkaleSolidity_detail::parseG2();

end:
        return std::nullopt;
    }
}

std::optional<component::G2> SkaleSolidity::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
        return std::nullopt;
    }

    std::vector<uint8_t> calldata;

    SkaleSolidity_detail::append(calldata, {0x0e, 0x13, 0xab, 0x52});

    if ( op.a == op.b ) {
        bool useDouble = false;

        try {
            useDouble = ds.Get<bool>();
        } catch ( ... ) { }

        if ( useDouble ) {
            return SkaleSolidity_detail::OpBLS_G2_Double(op);
        }
    }

    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.a));
    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.b));

    SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

    return SkaleSolidity_detail::parseG2();

end:
    return std::nullopt;
}


std::optional<component::Bignum> SkaleSolidity::OpBignumCalc(operation::BignumCalc& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::vector<uint8_t> calldata;

    if ( op.bn0.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }
    if ( op.bn1.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("GCD(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x8e, 0xc7, 0xeb, 0xee});

                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseU256(gas == 0);
            }
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            {
                SkaleSolidity_detail::append(calldata, {0xe6, 0x38, 0xd2, 0x31});

                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn2));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseU256(gas == 0);
            }
            break;
        case    CF_CALCOP("MulDiv(A,B,C)"):
            {
                //SkaleSolidity_detail::append(calldata, {0x54, 0xc1, 0x4b, 0x40});
                SkaleSolidity_detail::append(calldata, {0xaa, 0x9a, 0x09, 0x12});

                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn2));

                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

                return SkaleSolidity_detail::parseU256();
            }
            break;
        case    CF_CALCOP("Sqrt(A)"):
            {
                SkaleSolidity_detail::append(calldata, {0x3a, 0xcd, 0x10, 0xcf});
                //SkaleSolidity_detail::append(calldata, {0x67, 0x73, 0x42, 0xce});

                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));

                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), SkaleSolidity_detail::getGas(ds));

                return SkaleSolidity_detail::parseU256();
            }
            break;
    }

end:
    return std::nullopt;
}

std::optional<component::Fp2> SkaleSolidity::OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::vector<uint8_t> calldata;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x74, 0xba, 0x3a, 0x35});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseFp2(gas == 0);
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x36, 0x28, 0x8c, 0x4c});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseFp2(gas == 0);
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x08, 0xec, 0x7c, 0x4c});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseFp2(gas == 0);
            }
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x4d, 0x14, 0xff, 0x68});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseFp2(gas == 0);
            }
            break;
        case    CF_CALCOP("Sqr(A)"):
            {
                SkaleSolidity_detail::append(calldata, {0xd4, 0x5c, 0x63, 0x42});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseFp2(gas == 0);
            }
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            {
                SkaleSolidity_detail::append(calldata, {0x11, 0x36, 0x21, 0xef});
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn0));
                CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.bn1));

                const auto gas = SkaleSolidity_detail::getGas(ds);
                SkaleSolidity_Call(SkaleSolidity_detail::toGoSlice(calldata), gas);

                return SkaleSolidity_detail::parseBoolAsFp2(gas == 0);
            }
            break;
    }

end:
    return std::nullopt;
}

std::optional<bool> SkaleSolidity::OpBLS_Verify(operation::BLS_Verify& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    if ( op.curveType.Is(CF_ECC_CURVE("BN256")) ) {
        return std::nullopt;
    }

    std::vector<uint8_t> calldata;

    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.pub));
    CF_CHECK_TRUE(SkaleSolidity_detail::append(calldata, op.signature));
    SkaleSolidity_detail::append(calldata, {0x45, 0xff, 0x79, 0xc4});

end:
    return std::nullopt;
}

} /* namespace module */
} /* namespace cryptofuzz */
