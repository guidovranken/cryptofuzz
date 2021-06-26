#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-bls12-381.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_bls12_381::noble_bls12_381(void) :
    Module("noble-bls12-381"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_bls12_381_bytecode, noble_bls12_381_bytecode + noble_bls12_381_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

noble_bls12_381::~noble_bls12_381(void) {
    delete (JS*)js;
}

std::optional<component::BLS_PublicKey> noble_bls12_381::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
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

std::optional<component::BLS_Signature> noble_bls12_381::OpBLS_Sign(operation::BLS_Sign& op) {
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

std::optional<component::Bignum> noble_bls12_381::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_Compress_G2(operation::BLS_Compress_G2& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
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

std::optional<bool> noble_bls12_381::OpBLS_Verify(operation::BLS_Verify& op) {
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

std::optional<bool> noble_bls12_381::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
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

std::optional<bool> noble_bls12_381::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
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

std::optional<bool> noble_bls12_381::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
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

std::optional<bool> noble_bls12_381::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
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

std::optional<component::G1> noble_bls12_381::OpBLS_Aggregate_G1(operation::BLS_Aggregate_G1& op) {
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

std::optional<component::G2> noble_bls12_381::OpBLS_Aggregate_G2(operation::BLS_Aggregate_G2& op) {
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

std::optional<component::Bignum> noble_bls12_381::OpBignumCalc(operation::BignumCalc& op) {
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

bool noble_bls12_381::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
