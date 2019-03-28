#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#ifndef CRYPTOFUZZ_BORINGSSL
#include <openssl/kdf.h>
#endif
#include <openssl/pem.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class OpenSSL : public Module {
    private:
        const EVP_MD* toEVPMD(const component::DigestType& digestType) const;
        const EVP_CIPHER* toEVPCIPHER(const component::SymmetricCipherType cipherType) const;
        bool checkSetIVLength(const uint64_t cipherType, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputIvLength) const;
        bool checkSetKeyLength(const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputKeyLength) const;

#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::MAC> OpHMAC_EVP(operation::HMAC& op, Datasource& ds);
#endif
        std::optional<component::MAC> OpHMAC_HMAC(operation::HMAC& op, Datasource& ds);

#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Ciphertext> OpSymmetricEncrypt_BIO(operation::SymmetricEncrypt& op, Datasource& ds);
#endif
        std::optional<component::Ciphertext> OpSymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, Datasource& ds);

#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Ciphertext> OpSymmetricDecrypt_BIO(operation::SymmetricDecrypt& op, Datasource& ds);
#endif
        std::optional<component::Ciphertext> OpSymmetricDecrypt_EVP(operation::SymmetricDecrypt& op, Datasource& ds);
    public:
        OpenSSL(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
#endif
#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
#endif
#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) override;
#endif
#ifndef CRYPTOFUZZ_BORINGSSL
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
#endif
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Signature> OpSign(operation::Sign& op) override;
        std::optional<bool> OpVerify(operation::Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
