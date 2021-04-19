#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "elliptic.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

elliptic::elliptic(void) :
    Module("elliptic"),
    js(new JS()) {

    const std::vector<uint8_t> bc(elliptic_bytecode, elliptic_bytecode + elliptic_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

elliptic::~elliptic(void) {
    delete (JS*)js;
}

std::optional<component::ECDSA_Signature> elliptic::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    if (
            op.curveType.Get() != CF_ECC_CURVE("ed25519") &&
            op.curveType.Get() != CF_ECC_CURVE("ed448") ) {
        CF_CHECK_EQ(op.UseRFC6979Nonce(), true);
        CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("SHA256"));
    }

    {
        auto json = op.ToJSON();
        json["priv"] = util::DecToHex(op.priv.ToTrimmedString());
        json["operation"] = std::to_string(CF_OPERATION("ECDSA_Sign"));

        const auto res = ((JS*)js)->Run(json.dump());

        if ( res != std::nullopt ) {
            auto jsonRet = nlohmann::json::parse(*res);
            if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
                jsonRet["pub"][0] = util::HexToDec(jsonRet["pub"][0].get<std::string>());
            }
            ret = component::ECDSA_Signature(jsonRet);
        }
    }

end:

    return ret;
}

std::optional<bool> elliptic::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    auto json = op.ToJSON();
    json["pub_x"] = util::DecToHex(op.signature.pub.first.ToTrimmedString());
    json["pub_y"] = util::DecToHex(op.signature.pub.second.ToTrimmedString());
    json["sig_r"] = util::DecToHex(op.signature.signature.first.ToTrimmedString());
    json["sig_y"] = util::DecToHex(op.signature.signature.second.ToTrimmedString());
    json["operation"] = std::to_string(CF_OPERATION("ECDSA_Verify"));

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = nlohmann::json::parse(*res).get<bool>();
    }

    return ret;
}

std::optional<component::ECC_PublicKey> elliptic::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    auto json = op.ToJSON();
    json["priv"] = util::DecToHex(op.priv.ToTrimmedString());
    json["operation"] = std::to_string(CF_OPERATION("ECC_PrivateToPublic"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
            jsonRet[0] = util::HexToDec(jsonRet[0].get<std::string>());
        }
        ret = component::ECC_PublicKey(jsonRet);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
