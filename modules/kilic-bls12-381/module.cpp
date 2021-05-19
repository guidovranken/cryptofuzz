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

} /* namespace module */
} /* namespace cryptofuzz */
