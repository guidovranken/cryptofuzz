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

circl::circl(void) :
    Module("circl") {
}

std::string circl::getResult(void) const {
    auto res = circl_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> circl::getJsonResult(void) const {
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

template <class T> std::optional<T> circl::getResultAs(void) const {
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

std::optional<component::ECC_Point> circl::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_PrivateToPublic(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::ECC_Point> circl::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Add(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::ECC_Point> circl::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Mul(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::ECC_Point> circl::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Dbl(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::Bignum> circl::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        circl_bn254_BignumCalc_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        circl_bn254_BignumCalc_Fr(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    }

    return std::nullopt;
}

bool circl::SupportsModularBignumCalc(void) const {
    return true;
}

std::optional<component::G1> circl::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_PrivateToPublic(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> circl::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G1_Add(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> circl::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G1_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> circl::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G1_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<bool> circl::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    circl_BLS_IsG1OnCurve(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<bool> circl::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    circl_BLS_G1_IsEq(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<component::G1> circl::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_HashToG1(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G2> circl::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_PrivateToPublic_G2(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> circl::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G2_Add(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> circl::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G2_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> circl::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_G2_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<bool> circl::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    circl_BLS_IsG2OnCurve(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<bool> circl::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();

    circl_BLS_G2_IsEq(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<component::G2> circl::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_HashToG2(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G1> circl::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_Decompress_G1(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::Bignum> circl::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_Compress_G1(toGoSlice(jsonStr));

    return getResultAs<component::Bignum>();
}

std::optional<component::Fp12> circl::OpBLS_Pairing(operation::BLS_Pairing& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    circl_BLS_Pairing(toGoSlice(jsonStr));

    return getResultAs<component::Fp12>();
}

} /* namespace module */
} /* namespace cryptofuzz */
