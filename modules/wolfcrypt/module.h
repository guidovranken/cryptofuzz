#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class wolfCrypt : public Module {
    public:
        wolfCrypt(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
        std::optional<component::Key> OpKDF_PBKDF(operation::KDF_PBKDF& op) override;
        std::optional<component::Key> OpKDF_PBKDF1(operation::KDF_PBKDF1& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) override;
        std::optional<component::Key> OpKDF_X963(operation::KDF_X963& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECC_KeyPair> OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) override;
        std::optional<component::DH_KeyPair> OpDH_GenerateKeyPair(operation::DH_GenerateKeyPair& op) override;
        std::optional<component::Bignum> OpDH_Derive(operation::DH_Derive& op) override;
        std::optional<component::ECCSI_Signature> OpECCSI_Sign(operation::ECCSI_Sign& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECCSI_Verify(operation::ECCSI_Verify& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        std::optional<component::Ciphertext> OpECIES_Encrypt(operation::ECIES_Encrypt& op) override;
        std::optional<component::Cleartext> OpECIES_Decrypt(operation::ECIES_Decrypt& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<bool> OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) override;
        std::optional<bool> OpDSA_Verify(operation::DSA_Verify& op) override;
        std::optional<component::DSA_Signature> OpDSA_Sign(operation::DSA_Sign& op) override;
        std::optional<component::DSA_Parameters> OpDSA_GenerateParameters(operation::DSA_GenerateParameters& op) override;
        std::optional<component::Bignum> OpDSA_PrivateToPublic(operation::DSA_PrivateToPublic& op) override;
        std::optional<component::DSA_KeyPair> OpDSA_GenerateKeyPair(operation::DSA_GenerateKeyPair& op) override;
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
