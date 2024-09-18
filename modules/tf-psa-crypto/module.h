#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class TF_PSA_Crypto : public Module {
    public:
        TF_PSA_Crypto(void);
        ~TF_PSA_Crypto(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
