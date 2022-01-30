#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-secp256k1.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_secp256k1::noble_secp256k1(void) :
    Module("noble-secp256k1"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_secp256k1_bytecode, noble_secp256k1_bytecode + noble_secp256k1_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

noble_secp256k1::~noble_secp256k1(void) {
    delete (JS*)js;
}

std::optional<component::ECC_PublicKey> noble_secp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_PrivateToPublic"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_PublicKey(jsonRet);
    }

    return ret;
}

std::optional<component::ECDSA_Signature> noble_secp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    if ( !op.UseRFC6979Nonce() ) {
        return ret;
    }

    if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Sign"));

    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        json["cleartext"] = op.cleartext.SHA256().ToJSON();
    } else {
        json["cleartext"] = op.cleartext.ECDSA_Pad(32).ToJSON();
    }

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECDSA_Signature(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_secp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    
    if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        const auto padded = op.cleartext.ECDSA_Pad(32);
        static const std::vector<uint8_t> curve_order
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
        if ( padded.IsZero() || padded.Get() == curve_order ) {
            return ret;
        }
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Verify"));

    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        json["cleartext"] = op.cleartext.SHA256().ToJSON();
    } 

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = nlohmann::json::parse(*res).get<bool>();
    }

    return ret;
}

std::optional<component::ECC_Point> noble_secp256k1::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Add"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}

std::optional<component::ECC_Point> noble_secp256k1::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Mul"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}

std::optional<component::ECC_Point> noble_secp256k1::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Neg"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}
std::optional<component::ECC_Point> noble_secp256k1::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECC_Point_Dbl"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECC_Point(jsonRet);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
