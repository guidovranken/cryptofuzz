#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>

namespace cryptofuzz {
namespace module {

class libsodium : public Module {
    public:
        libsodium(void);
        std::optional<component::Ciphertext> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
