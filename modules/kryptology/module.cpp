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

static GoSlice toGoSlice(std::string& in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
}

Kryptology::Kryptology(void) :
    Module("Kryptology") {
}

std::string Kryptology::getResult(void) const {
    auto res = Kryptology_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> Kryptology::getJsonResult(void) const {
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

template <class T> std::optional<T> Kryptology::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    auto j = getJsonResult();
    if ( j != std::nullopt ) {
        ret = T(*j);
    }

    return ret;
}

std::optional<component::Bignum> Kryptology::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_BignumCalc_bls12381_Fr(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_BignumCalc_bls12381_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else if ( op.modulo->ToTrimmedString() == "115792089237316195423570985008687907853269984665640564039457584007908834671663" ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_BignumCalc_k256_Fp(toGoSlice(jsonStr));

        return getResultAs<component::Bignum>();
    } else {
        return std::nullopt;
    }

}

std::optional<component::ECC_Point> Kryptology::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Add_k256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Add_p256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else {
        return std::nullopt;
    }
}

std::optional<component::ECC_Point> Kryptology::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Mul_k256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Mul_p256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else {
        return std::nullopt;
    }
}

std::optional<component::ECC_Point> Kryptology::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Dbl_k256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        auto json = op.ToJSON();
        auto jsonStr = json.dump();
        Kryptology_ECC_Point_Dbl_p256(toGoSlice(jsonStr));

        return getResultAs<component::ECC_Point>();
    } else {
        return std::nullopt;
    }
}

bool Kryptology::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
