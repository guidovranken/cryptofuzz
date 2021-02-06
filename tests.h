#pragma once

#include <cryptofuzz/operations.h>
#include <cryptofuzz/components.h>

namespace cryptofuzz {
namespace tests {

void test(const operation::Digest& op, const std::optional<component::Digest>& result);
void test(const operation::HMAC& op, const std::optional<component::MAC>& result);
void test(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result);
void test(const operation::SymmetricDecrypt& op, const std::optional<component::Cleartext>& result);
void test(const operation::CMAC& op, const std::optional<component::MAC>& result);
void test(const operation::KDF_SCRYPT& op, const std::optional<component::Key>& result);
void test(const operation::KDF_HKDF& op, const std::optional<component::Key>& result);
void test(const operation::KDF_TLS1_PRF& op, const std::optional<component::Key>& result);
void test(const operation::KDF_PBKDF& op, const std::optional<component::Key>& result);
void test(const operation::KDF_PBKDF1& op, const std::optional<component::Key>& result);
void test(const operation::KDF_PBKDF2& op, const std::optional<component::Key>& result);
void test(const operation::KDF_ARGON2& op, const std::optional<component::Key>& result);
void test(const operation::KDF_SSH& op, const std::optional<component::Key>& result);
void test(const operation::KDF_X963& op, const std::optional<component::Key>& result);
void test(const operation::KDF_BCRYPT& op, const std::optional<component::Key>& result);
void test(const operation::KDF_SP_800_108& op, const std::optional<component::Key>& result);
void test(const operation::Sign& op, const std::optional<component::Signature>& result);
void test(const operation::Verify& op, const std::optional<bool>& result);
void test(const operation::ECC_PrivateToPublic& op, const std::optional<component::ECC_PublicKey>& result);
void test(const operation::ECC_ValidatePubkey& op, const std::optional<bool>& result);
void test(const operation::ECC_GenerateKeyPair& op, const std::optional<component::ECC_KeyPair>& result);
void test(const operation::ECDSA_Sign& op, const std::optional<component::ECDSA_Signature>& result);
void test(const operation::ECDSA_Verify& op, const std::optional<bool>& result);
void test(const operation::ECDH_Derive& op, const std::optional<component::Secret>& result);
void test(const operation::ECIES_Encrypt& op, const std::optional<component::Ciphertext>& result);
void test(const operation::DH_GenerateKeyPair& op, const std::optional<component::DH_KeyPair>& result);
void test(const operation::DH_Derive& op, const std::optional<component::Bignum>& result);
void test(const operation::BignumCalc& op, const std::optional<component::Bignum>& result);
void test(const operation::BLS_PrivateToPublic& op, const std::optional<component::BLS_PublicKey>& result);
void test(const operation::BLS_Sign& op, const std::optional<component::BLS_Signature>& result);
void test(const operation::BLS_Verify& op, const std::optional<bool>& result);
void test(const operation::BLS_Pairing& op, const std::optional<bool>& result);
void test(const operation::BLS_HashToG1& op, const std::optional<component::G1>& result);
void test(const operation::BLS_HashToG2& op, const std::optional<component::G2>& result);

} /* namespace tests */
} /* namespace cryptofuzz */
