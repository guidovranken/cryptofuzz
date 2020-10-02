#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "crypto-js.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

crypto_js::crypto_js(void) :
    Module("crypto-js"),
    js(new JS()) {

    const std::vector<uint8_t> bc(crypto_js_bytecode, crypto_js_bytecode + crypto_js_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

crypto_js::~crypto_js(void) {
    delete (JS*)js;
}

template <class T> std::optional<T> getResultAs(const std::string& s) {
    return T(nlohmann::json::parse(s));
}

template <class ReturnType, class OperationType, uint64_t OperationID>
std::optional<ReturnType> Run(JS* js, OperationType& op, std::optional<Buffer> toParts = std::nullopt, const std::string partsName = "cleartext") {
    std::optional<ReturnType> ret = std::nullopt;

    auto json = op.ToJSON();

    if ( toParts != std::nullopt ) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        util::Multipart parts = util::ToParts(ds, *toParts);

        std::vector<std::string> hexParts;

        for (const auto& part : parts) {
            std::string asHex;
            boost::algorithm::hex(std::vector<uint8_t>(part.first, part.first + part.second), std::back_inserter(asHex));
            hexParts.push_back(asHex);
        }

        json[partsName] = hexParts;
    }

    json["operation"] = std::to_string( OperationID );

    const auto res = js->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = getResultAs<ReturnType>(*res);
    }

    return ret;
}

std::optional<component::Digest> crypto_js::OpDigest(operation::Digest& op) {
    return Run<component::Digest, operation::Digest, CF_OPERATION("Digest")>((JS*)js, op, op.cleartext);
}

std::optional<component::MAC> crypto_js::OpHMAC(operation::HMAC& op) {
    return Run<component::MAC, operation::HMAC, CF_OPERATION("HMAC")>((JS*)js, op, op.cleartext);
}

std::optional<component::Ciphertext> crypto_js::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<Buffer> toParts = std::nullopt;
    if ( op.cipher.cipherType.Get() == CF_CIPHER("RC4") || op.cipher.cipherType.Get() == CF_CIPHER("RABBIT") ) {
        toParts = op.cleartext;
    }
    return Run<component::Ciphertext, operation::SymmetricEncrypt, CF_OPERATION("SymmetricEncrypt")>((JS*)js, op, toParts);
}

std::optional<component::Cleartext> crypto_js::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<Buffer> toParts = std::nullopt;
    if ( op.cipher.cipherType.Get() == CF_CIPHER("RC4") || op.cipher.cipherType.Get() == CF_CIPHER("RABBIT") ) {
        toParts = op.ciphertext;
    }
    return Run<component::Cleartext, operation::SymmetricDecrypt, CF_OPERATION("SymmetricDecrypt")>((JS*)js, op, toParts, "ciphertext");
}

std::optional<component::Key> crypto_js::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    return Run<component::Key, operation::KDF_PBKDF2, CF_OPERATION("KDF_PBKDF2")>((JS*)js, op);
}

} /* namespace module */
} /* namespace cryptofuzz */
