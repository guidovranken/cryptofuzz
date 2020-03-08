#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
 #if defined(CRYPTOFUZZ_BORINGSSL)
  #include <openssl/hkdf.h>
 #else
  #include <openssl/kdf.h>
 #endif
#endif
#include <openssl/pem.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class OpenSSL : public Module {
    private:
        bool isAEAD(const EVP_CIPHER* ctx, const uint64_t cipherType) const;
        const EVP_MD* toEVPMD(const component::DigestType& digestType) const;
        const EVP_CIPHER* toEVPCIPHER(const component::SymmetricCipherType cipherType) const;
#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
        const EVP_AEAD* toEVPAEAD(const component::SymmetricCipherType cipherType) const;
#endif

        bool checkSetIVLength(const uint64_t cipherType, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputIvLength) const;
        bool checkSetKeyLength(const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputKeyLength) const;

#if !defined(CRYPTOFUZZ_BORINGSSL)
        std::optional<component::MAC> OpHMAC_EVP(operation::HMAC& op, Datasource& ds);
#endif
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        HMAC_CTX* Copy_HMAC_CTX(HMAC_CTX* ctx, Datasource& ds);
        std::optional<component::MAC> OpHMAC_HMAC(operation::HMAC& op, Datasource& ds);
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL)
        std::optional<component::Ciphertext> OpSymmetricEncrypt_BIO(operation::SymmetricEncrypt& op, Datasource& ds);
#endif
        std::optional<component::Ciphertext> OpSymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, Datasource& ds);
#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
        std::optional<component::Ciphertext> AEAD_Encrypt(operation::SymmetricEncrypt& op, Datasource& ds);
        std::optional<component::Cleartext> AEAD_Decrypt(operation::SymmetricDecrypt& op, Datasource& ds);
#endif
        std::optional<component::Ciphertext> AES_Encrypt(operation::SymmetricEncrypt& op, Datasource& ds);
        std::optional<component::Cleartext> AES_Decrypt(operation::SymmetricDecrypt& op, Datasource& ds);

#if !defined(CRYPTOFUZZ_BORINGSSL)
        std::optional<component::Cleartext> OpSymmetricDecrypt_BIO(operation::SymmetricDecrypt& op, Datasource& ds);
#endif
        std::optional<component::Cleartext> OpSymmetricDecrypt_EVP(operation::SymmetricDecrypt& op, Datasource& ds);
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_SCRYPT_EVP_PKEY(operation::KDF_SCRYPT& op) const;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_SCRYPT_EVP_KDF(operation::KDF_SCRYPT& op) const;
#endif
    public:
        OpenSSL(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
        std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) override;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_ARGON2(operation::KDF_ARGON2& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_SSH(operation::KDF_SSH& op) override;
        std::optional<component::Key> OpKDF_X963(operation::KDF_X963& op) override;
#endif
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Signature> OpSign(operation::Sign& op) override;
        std::optional<bool> OpVerify(operation::Verify& op) override;
#if !(defined(CRYPTOFUZZ_LIBRESSL) && defined(SANITIZER_MSAN))
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECC_KeyPair> OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
#endif
};

} /* namespace module */
} /* namespace cryptofuzz */
