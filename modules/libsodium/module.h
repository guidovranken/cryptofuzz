#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>

namespace cryptofuzz {
namespace module {

class libsodium : public Module {
    private:
        std::optional<component::Digest> SHA256(operation::Digest& op) const;
        std::optional<component::Digest> SHA512(operation::Digest& op) const;
        std::optional<component::MAC> HMAC_SHA256(operation::HMAC& op) const;
        std::optional<component::MAC> HMAC_SHA512(operation::HMAC& op) const;
        std::optional<component::MAC> HMAC_SHA512256(operation::HMAC& op) const;
    public:
        libsodium(void);
        std::optional<component::Ciphertext> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
