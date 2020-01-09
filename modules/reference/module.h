#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Reference : public Module {
        const bool haveSSE42;
        std::optional<component::Digest> WHIRLPOOL(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> GROESTL(operation::Digest& op, Datasource& ds, const size_t bitSize) const;
        std::optional<component::Digest> XXHASH64_OneShot(operation::Digest& op) const;
        std::optional<component::Digest> XXHASH64_Streaming(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> XXHASH64(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> XXHASH32_OneShot(operation::Digest& op) const;
        std::optional<component::Digest> XXHASH32_Streaming(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> XXHASH32(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> BLAKE3(operation::Digest& op, Datasource& ds) const;
        std::optional<component::MAC> BLAKE3_MAC(operation::HMAC& op, Datasource& ds) const;
    public:
        Reference(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Key> OpKDF_ARGON2(operation::KDF_ARGON2& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
