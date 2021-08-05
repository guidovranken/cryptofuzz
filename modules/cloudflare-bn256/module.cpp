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

Cloudflare_bn256::Cloudflare_bn256(void) :
    Module("Cloudflare_bn256") {
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

static GoSlice toGoSlice(std::string& in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
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

} /* namespace module */
} /* namespace cryptofuzz */
