#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Monocypher : public Module {
    public:
        Monocypher(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        //std::optional<component::Key> OpKDF_ARGON2(operation::KDF_ARGON2& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
