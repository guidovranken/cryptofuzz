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

Decred::Decred(void) :
    Module("Decred") {
}

std::string Decred::getResult(void) const {
    auto res = Decred_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> Decred::getJsonResult(void) const {
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

template <class T> std::optional<T> Decred::getResultAs(void) const {
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

std::optional<component::ECC_PublicKey> Decred::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    auto jsonStr = json.dump();
    Decred_Cryptofuzz_OpECC_PrivateToPublic(toGoSlice(jsonStr));

    return getResultAs<component::ECC_PublicKey>();
}

std::optional<bool> Decred::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    json["digestType"] = boost::lexical_cast<uint64_t>(json["digestType"].get<std::string>());
    auto jsonStr = json.dump();
    Decred_Cryptofuzz_OpECDSA_Verify(toGoSlice(jsonStr));

    return getResultAs<bool>();
}

std::optional<component::ECDSA_Signature> Decred::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( op.UseSpecifiedNonce() ) {
        return std::nullopt;
    }

    auto json = op.ToJSON();
    json["curveType"] = boost::lexical_cast<uint64_t>(json["curveType"].get<std::string>());
    json["digestType"] = boost::lexical_cast<uint64_t>(json["digestType"].get<std::string>());
    auto jsonStr = json.dump();
    Decred_Cryptofuzz_OpECDSA_Sign(toGoSlice(jsonStr));

    auto j = getJsonResult();
    if ( j == std::nullopt ) {
        return std::nullopt;
    }

    const auto pub_x = (*j)["pub"][0].get<std::string>();
    const auto pub_y = (*j)["pub"][1].get<std::string>();
    const auto sig_hex = (*j)["sig"].get<std::string>();
    std::vector<uint8_t> sig_bytes;
    boost::algorithm::unhex(sig_hex, std::back_inserter(sig_bytes));
    const auto sig = util::SignatureFromDER(sig_bytes);
    CF_ASSERT(sig != std::nullopt, "Cannot parse signature");

    return component::ECDSA_Signature{ {sig->first, sig->second}, {pub_x, pub_y} };
}

} /* namespace module */
} /* namespace cryptofuzz */
