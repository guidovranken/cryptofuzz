#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-ed25519.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_ed25519::noble_ed25519(void) :
    Module("noble-ed25519"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_ed25519_bytecode, noble_ed25519_bytecode + noble_ed25519_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

noble_ed25519::~noble_ed25519(void) {
    delete (JS*)js;
}

std::optional<component::ECC_PublicKey> noble_ed25519::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    
    if ( !op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
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

std::optional<component::ECDSA_Signature> noble_ed25519::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        return ret;
    }

    if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }
    
    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Sign"));

    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        json["cleartext"] = op.cleartext.SHA256().ToJSON();
    }

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::ECDSA_Signature(jsonRet);
    }

    return ret;
}

std::optional<bool> noble_ed25519::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        return ret;
    }
    
    if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
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

} /* namespace module */
} /* namespace cryptofuzz */
