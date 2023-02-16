#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-curves.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_curves::noble_curves(void) :
    Module("noble-curves"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_curves_bytecode, noble_curves_bytecode + noble_curves_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

noble_curves::~noble_curves(void) {
    delete (JS*)js;
}
// ECC
std::optional<component::ECC_PublicKey> noble_curves::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_PrivateToPublic"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_PublicKey(jsonRet);
    }

    return ret;
}

std::optional<component::ECDSA_Signature> noble_curves::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    if ( op.curveType.Get() != CF_ECC_CURVE("ed25519") && op.curveType.Get() != CF_ECC_CURVE("ed448") && !op.UseRFC6979Nonce() ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Sign"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {

        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECDSA_Signature(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Verify"));


    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = nlohmann::json::parse(*res).get<bool>();
    }

    return ret;
}

std::optional<component::ECC_Point> noble_curves::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Add"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}

std::optional<component::ECC_Point> noble_curves::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Mul"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}

std::optional<component::ECC_Point> noble_curves::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Neg"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}
std::optional<component::ECC_Point> noble_curves::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Dbl"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}
// BLS

std::optional<component::BLS_PublicKey> noble_curves::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    std::optional<component::BLS_PublicKey> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_PrivateToPublic"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::BLS_PublicKey(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_HashToG1"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_HashToG2"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<component::BLS_Signature> noble_curves::OpBLS_Sign(operation::BLS_Sign& op) {
    std::optional<component::BLS_Signature> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Sign"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::BLS_Signature(jsonRet);
    }

    return ret;
}

std::optional<component::Bignum> noble_curves::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Compress_G1"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Bignum(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Decompress_G1"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_Compress_G2(operation::BLS_Compress_G2& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Compress_G2"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Decompress_G2"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpBLS_Verify(operation::BLS_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Verify"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = bool(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_IsG1OnCurve"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = bool(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_IsG2OnCurve"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = bool(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G1_Add"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G1_Mul"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G1_Neg"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G1_IsEq"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = bool(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G2_Add"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G2_Mul"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G2_Neg"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_curves::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_G2_IsEq"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = bool(jsonRet);
    }

    return ret;
}

std::optional<component::G1> noble_curves::OpBLS_Aggregate_G1(operation::BLS_Aggregate_G1& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Aggregate_G1"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G1(jsonRet);
    }

    return ret;
}

std::optional<component::G2> noble_curves::OpBLS_Aggregate_G2(operation::BLS_Aggregate_G2& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("BLS_Aggregate_G2"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::G2(jsonRet);
    }

    return ret;
}

std::optional<component::Bignum> noble_curves::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    bool P;
    if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        P = true;
    } else if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        P = false;
    } else {
        return std::nullopt;
    }


    std::optional<component::Bignum> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = P ? std::to_string(CF_OPERATION("BignumCalc_Mod_BLS12_381_P")) : std::to_string(CF_OPERATION("BignumCalc_Mod_BLS12_381_R"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Bignum(jsonRet);
    }

    return ret;
}

bool noble_curves::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
