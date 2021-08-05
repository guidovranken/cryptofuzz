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
    Module("Gnark_bn254") {
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

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G1_Add(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G1_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G1> Gnark_bn254::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G1_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G1>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G2_Add(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G2_Mul(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::G2> Gnark_bn254::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Gnark_bn254_BLS_G2_Neg(toGoSlice(jsonStr));

    return getResultAs<component::G2>();
}

std::optional<component::Bignum> Gnark_bn254::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Gnark_bn254_BignumCalc_Fr(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    }

    return std::nullopt;
}

bool Gnark_bn254::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
