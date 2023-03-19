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

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::MAC> OpHMAC_EVP(operation::HMAC& op, Datasource& ds);
#endif
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_SCRYPT_EVP_PKEY(operation::KDF_SCRYPT& op) const;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_SCRYPT_EVP_KDF(operation::KDF_SCRYPT& op) const;
#endif
    public:
        OpenSSL(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
#if !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
#endif
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) override;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_PBKDF(operation::KDF_PBKDF& op) override;
#endif
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
        std::optional<component::Key> OpKDF_ARGON2(operation::KDF_ARGON2& op) override;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Key> OpKDF_SSH(operation::KDF_SSH& op) override;
        std::optional<component::Key> OpKDF_X963(operation::KDF_X963& op) override;
        std::optional<component::Key> OpKDF_SP_800_108(operation::KDF_SP_800_108& op) override;
#endif
#if !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
#endif
#if !(defined(CRYPTOFUZZ_LIBRESSL) && defined(SANITIZER_MSAN))
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
#endif
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECC_KeyPair> OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) override;
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
#endif
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::DH_KeyPair> OpDH_GenerateKeyPair(operation::DH_GenerateKeyPair& op) override;
#endif
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        std::optional<component::Bignum> OpDH_Derive(operation::DH_Derive& op) override;
#endif
        std::optional<component::DSA_Parameters> OpDSA_GenerateParameters(operation::DSA_GenerateParameters& op) override;
        std::optional<component::Bignum> OpDSA_PrivateToPublic(operation::DSA_PrivateToPublic& op) override;
        std::optional<component::DSA_Signature> OpDSA_Sign(operation::DSA_Sign& op) override;
        std::optional<bool> OpDSA_Verify(operation::DSA_Verify& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<bool> OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
#endif
};

} /* namespace module */
} /* namespace cryptofuzz */
