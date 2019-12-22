#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class CryptoPP : public Module {
    public:
        CryptoPP(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
        std::optional<component::Key> OpKDF_PBKDF(operation::KDF_PBKDF& op) override;
        std::optional<component::Key> OpKDF_PBKDF1(operation::KDF_PBKDF1& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
