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

kilic_bls12_381::kilic_bls12_381(void) :
    Module("kilic-bls12-381") {
}

std::string kilic_bls12_381::getResult(void) const {
    auto res = kilic_bls12_381_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> kilic_bls12_381::getJsonResult(void) const {
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

template <class T> std::optional<T> kilic_bls12_381::getResultAs(void) const {
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
        
std::optional<component::BLS_PublicKey> kilic_bls12_381::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    auto json = op.ToJSON();
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic(toGoSlice(jsonStr));

    return getResultAs<component::BLS_PublicKey>();
}

std::optional<component::G2> kilic_bls12_381::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    auto json = op.ToJSON();
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic_G2(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<bool> kilic_bls12_381::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_IsG1OnCurve(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<component::G1> kilic_bls12_381::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G1_Add(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> kilic_bls12_381::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G1_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> kilic_bls12_381::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G1_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<bool> kilic_bls12_381::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_IsG2OnCurve(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<component::G2> kilic_bls12_381::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G2_Add(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> kilic_bls12_381::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G2_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> kilic_bls12_381::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_G2_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::Fp12> kilic_bls12_381::OpBLS_Pairing(operation::BLS_Pairing& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    kilic_bls12_381_Cryptofuzz_OpBLS_Pairing(toGoSlice(jsonStr));

    return getResultAs<component::Fp12>();
}

std::optional<component::Bignum> kilic_bls12_381::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
#if 0
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        kilic_bls12_381_Cryptofuzz_OpBignumCalc_Fp(toGoSlice(jsonStr));
        return getResultAs<component::Bignum>();
#endif
        return std::nullopt;
    } else if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        kilic_bls12_381_Cryptofuzz_OpBignumCalc_Fr(toGoSlice(jsonStr));
        return getResultAs<component::Bignum>();
    }

    return std::nullopt;
}

bool kilic_bls12_381::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
