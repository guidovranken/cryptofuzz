#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <cryptofuzz/util.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class NSS : public Module {
    public:
        NSS(void);
        ~NSS();
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
