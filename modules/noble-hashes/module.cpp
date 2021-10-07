#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "noble-hashes.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

noble_hashes::noble_hashes(void) :
    Module("noble-hashes"),
    js(new JS()) {

    const std::vector<uint8_t> bc(noble_hashes_bytecode, noble_hashes_bytecode + noble_hashes_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

noble_hashes::~noble_hashes(void) {
    delete (JS*)js;
}

namespace noble_hashes_detail {
    std::optional<util::Multipart> ToParts(const component::Cleartext& ct, fuzzing::datasource::Datasource& ds) {
        bool toParts  = false;
        try {
            toParts = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( toParts == false ) {
            return std::nullopt;
        }

        return util::ToParts(ds, ct);
    }

    void AddParts(nlohmann::json& json, const component::Cleartext& ct, fuzzing::datasource::Datasource& ds) {
        const auto parts = noble_hashes_detail::ToParts(ct, ds);

        if ( parts != std::nullopt ) {
            json["haveParts"] = true;
            json["parts"] = nlohmann::json::array();
            for (const auto& part : *parts) {
                const auto part_ = Buffer(part.first, part.second);
                json["parts"].push_back( part_.ToJSON() );
            }
        } else {
            json["haveParts"] = false;
        }
    }
}

std::optional<component::Digest> noble_hashes::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("Digest"));

    CF_NORET(noble_hashes_detail::AddParts(json, op.cleartext, ds));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Digest(jsonRet);
    }

    return ret;
}

std::optional<component::MAC> noble_hashes::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("HMAC"));

    CF_NORET(noble_hashes_detail::AddParts(json, op.cleartext, ds));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::MAC(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("KDF_HKDF"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

std::optional<component::Key> noble_hashes::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    auto json = op.ToJSON();
    json["operation"] = std::to_string(CF_OPERATION("KDF_PBKDF2"));

    auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        auto jsonRet = nlohmann::json::parse(*res);
        ret = component::Key(jsonRet);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
