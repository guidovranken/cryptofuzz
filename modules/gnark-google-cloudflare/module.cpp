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

Gnark_bn254::Gnark_bn254(void) :
    Module("gnark-bn254") {
}

std::string Gnark_bn254::getResult(void) const {
    auto res = Gnark_bn254_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> Gnark_bn254::getJsonResult(void) const {
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

template <class T> std::optional<T> Gnark_bn254::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    auto j = getJsonResult();
    if ( j != std::nullopt ) {
        ret = T(*j);
    }

    return ret;
}

static GoSlice toGoSlice(std::string& in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
}

std::optional<bool> Gnark_bn254::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_IsG1OnCurve(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_IsG1OnCurve(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<bool>();
}

std::optional<bool> Gnark_bn254::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_IsG2OnCurve(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_IsG2OnCurve(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<bool>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G1_Add(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        Gnark_bls12_377_BLS_G1_Add(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G1_Add(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G1>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G1_Mul(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        Gnark_bls12_377_BLS_G1_Mul(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G1_Mul(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G1>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G1_Neg(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G1_Neg(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G1>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G2_Add(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G2_Add(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G2>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G2_Mul(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        Gnark_bls12_377_BLS_G2_Mul(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G2_Mul(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G2>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G2_Neg(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_G2_Neg(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G2>();
}

std::optional<component::Fp12> Gnark_bn254::OpBLS_Pairing(operation::BLS_Pairing& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_Pairing(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::Fp12>();
}

std::optional<component::Fp12> Gnark_bn254::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_FinalExp(toGoSlice(jsonStr));
    } else if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Gnark_bn254_BLS_FinalExp(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::Fp12>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        Gnark_bls12_381_BLS_G1_MultiExp(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::G1>();
}

std::optional<component::Fp2> Gnark_bn254::OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) {
    auto json = op.ToJSON();
    auto jsonStr = json.dump();
    Gnark_bn254_BignumCalc_bls2381_Fp2(toGoSlice(jsonStr));
    return getResultAs<component::Fp2>();
}

std::optional<component::Fp12> Gnark_bn254::OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) {
    auto json = op.ToJSON();
    auto jsonStr = json.dump();
    Gnark_bn254_BignumCalc_bls12381_Fp12(toGoSlice(jsonStr));
    return getResultAs<component::Fp12>();
}

std::optional<component::Bignum> Gnark_bn254::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_bn254_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_bn254_Fr(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_bls12381_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_bls12381_Fr(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    }

    return std::nullopt;
}

bool Gnark_bn254::SupportsModularBignumCalc(void) const {
    return true;
}

Cloudflare_bn256::Cloudflare_bn256(void) :
    Module("cloudflare-bn256") {
}

std::string Cloudflare_bn256::getResult(void) const {
    auto res = Cloudflare_bn256_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> Cloudflare_bn256::getJsonResult(void) const {
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

template <class T> std::optional<T> Cloudflare_bn256::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    auto j = getJsonResult();
    if ( j != std::nullopt ) {
        ret = T(*j);
    }

    return ret;
}

std::optional<component::G1> Cloudflare_bn256::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G1_Add(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Cloudflare_bn256::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G1_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Cloudflare_bn256::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G1_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G2> Cloudflare_bn256::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G2_Add(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> Cloudflare_bn256::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G2_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> Cloudflare_bn256::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Cloudflare_bn256_BLS_G2_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::Fp12> Cloudflare_bn256::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        Cloudflare_bn256_BLS_FinalExp(toGoSlice(jsonStr));
    } else {
        return std::nullopt;
    }

    return getResultAs<component::Fp12>();
}

Google_bn256::Google_bn256(void) :
    Module("google-bn256") {
}

std::string Google_bn256::getResult(void) const {
    auto res = Google_bn256_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> Google_bn256::getJsonResult(void) const {
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

template <class T> std::optional<T> Google_bn256::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    auto j = getJsonResult();
    if ( j != std::nullopt ) {
        ret = T(*j);
    }

    return ret;
}

std::optional<component::G1> Google_bn256::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Google_bn256_BLS_G1_Add(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Google_bn256::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Google_bn256_BLS_G1_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Google_bn256::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Google_bn256_BLS_G1_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G2> Google_bn256::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Google_bn256_BLS_G2_Add(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> Google_bn256::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Google_bn256_BLS_G2_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

} /* namespace module */
} /* namespace cryptofuzz */
