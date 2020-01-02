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
std::optional<ReturnType> Run(JS* js, OperationType& op) {
    std::optional<ReturnType> ret = std::nullopt;

    auto json = op.ToJSON();
    json["operation"] = std::to_string( OperationID );

    const auto res = js->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = getResultAs<ReturnType>(*res);
    }

    return ret;
}

std::optional<component::Digest> crypto_js::OpDigest(operation::Digest& op) {
    return Run<component::Digest, operation::Digest, CF_OPERATION("Digest")>((JS*)js, op);
}

std::optional<component::MAC> crypto_js::OpHMAC(operation::HMAC& op) {
    return Run<component::MAC, operation::HMAC, CF_OPERATION("HMAC")>((JS*)js, op);
}

std::optional<component::Key> crypto_js::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    return Run<component::Key, operation::KDF_PBKDF2, CF_OPERATION("KDF_PBKDF2")>((JS*)js, op);
}

} /* namespace module */
} /* namespace cryptofuzz */
