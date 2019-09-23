#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/aria.h>
#include <mbedtls/camellia.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class mbedTLS : public Module {
    private:
        const mbedtls_cipher_info_t* to_mbedtls_cipher_info_t(const component::SymmetricCipherType cipherType) const;
        mbedtls_md_type_t to_mbedtls_md_type_t(const component::DigestType& digestType) const;
        std::optional<component::Ciphertext> encrypt_AEAD(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> decrypt_AEAD(operation::SymmetricDecrypt& op) const;
    public:
        mbedTLS(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
