#pragma once

#include <cryptofuzz/operations.h>
#include <cryptofuzz/components.h>

namespace cryptofuzz {
namespace tests {

void test(const operation::Digest& op, const std::optional<component::Digest>& result);
void test(const operation::HMAC& op, const std::optional<component::MAC>& result);
void test(const operation::UMAC& op, const std::optional<component::MAC>& result);
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
void test(const operation::ECC_PrivateToPublic& op, const std::optional<component::ECC_PublicKey>& result);
void test(const operation::ECC_ValidatePubkey& op, const std::optional<bool>& result);
void test(const operation::ECC_GenerateKeyPair& op, const std::optional<component::ECC_KeyPair>& result);
void test(const operation::ECCSI_Sign& op, const std::optional<component::ECCSI_Signature>& result);
void test(const operation::ECDSA_Sign& op, const std::optional<component::ECDSA_Signature>& result);
void test(const operation::ECGDSA_Sign& op, const std::optional<component::ECGDSA_Signature>& result);
void test(const operation::ECRDSA_Sign& op, const std::optional<component::ECRDSA_Signature>& result);
void test(const operation::Schnorr_Sign& op, const std::optional<component::Schnorr_Signature>& result);
void test(const operation::ECCSI_Verify& op, const std::optional<bool>& result);
void test(const operation::ECDSA_Verify& op, const std::optional<bool>& result);
void test(const operation::ECGDSA_Verify& op, const std::optional<bool>& result);
void test(const operation::ECRDSA_Verify& op, const std::optional<bool>& result);
void test(const operation::Schnorr_Verify& op, const std::optional<bool>& result);
void test(const operation::ECDSA_Recover& op, const std::optional<component::ECC_PublicKey>& result);
void test(const operation::DSA_Verify& op, const std::optional<bool>& result);
void test(const operation::DSA_Sign& op, const std::optional<component::DSA_Signature>& result);
void test(const operation::DSA_GenerateParameters& op, const std::optional<component::DSA_Parameters>& result);
void test(const operation::DSA_PrivateToPublic& op, const std::optional<component::Bignum>& result);
void test(const operation::DSA_GenerateKeyPair& op, const std::optional<component::DSA_KeyPair>& result);
void test(const operation::ECDH_Derive& op, const std::optional<component::Secret>& result);
void test(const operation::ECIES_Encrypt& op, const std::optional<component::Ciphertext>& result);
void test(const operation::ECIES_Decrypt& op, const std::optional<component::Cleartext>& result);
void test(const operation::ECC_Point_Add& op, const std::optional<component::ECC_Point>& result);
void test(const operation::ECC_Point_Sub& op, const std::optional<component::ECC_Point>& result);
void test(const operation::ECC_Point_Mul& op, const std::optional<component::ECC_Point>& result);
void test(const operation::ECC_Point_Neg& op, const std::optional<component::ECC_Point>& result);
void test(const operation::ECC_Point_Dbl& op, const std::optional<component::ECC_Point>& result);
void test(const operation::ECC_Point_Cmp& op, const std::optional<bool>& result);
void test(const operation::DH_GenerateKeyPair& op, const std::optional<component::DH_KeyPair>& result);
void test(const operation::DH_Derive& op, const std::optional<component::Bignum>& result);
void test(const operation::BignumCalc& op, const std::optional<component::Bignum>& result);
void test(const operation::BignumCalc_Fp2& op, const std::optional<component::Fp2>& result);
void test(const operation::BignumCalc_Fp12& op, const std::optional<component::Fp12>& result);
void test(const operation::BLS_PrivateToPublic& op, const std::optional<component::BLS_PublicKey>& result);
void test(const operation::BLS_PrivateToPublic_G2& op, const std::optional<component::G2>& result);
void test(const operation::BLS_Sign& op, const std::optional<component::BLS_Signature>& result);
void test(const operation::BLS_Verify& op, const std::optional<bool>& result);
void test(const operation::BLS_BatchSign& op, const std::optional<component::BLS_BatchSignature>& result);
void test(const operation::BLS_BatchVerify& op, const std::optional<bool>& result);
void test(const operation::BLS_Aggregate_G1& op, const std::optional<component::G1>& result);
void test(const operation::BLS_Aggregate_G2& op, const std::optional<component::G2>& result);
void test(const operation::BLS_Pairing& op, const std::optional<component::Fp12>& result);
void test(const operation::BLS_MillerLoop& op, const std::optional<component::Fp12>& result);
void test(const operation::BLS_FinalExp& op, const std::optional<component::Fp12>& result);
void test(const operation::BLS_HashToG1& op, const std::optional<component::G1>& result);
void test(const operation::BLS_HashToG2& op, const std::optional<component::G2>& result);
void test(const operation::BLS_MapToG1& op, const std::optional<component::G1>& result);
void test(const operation::BLS_MapToG2& op, const std::optional<component::G2>& result);
void test(const operation::BLS_IsG1OnCurve& op, const std::optional<bool>& result);
void test(const operation::BLS_IsG2OnCurve& op, const std::optional<bool>& result);
void test(const operation::BLS_GenerateKeyPair& op, const std::optional<component::BLS_KeyPair>& result);
void test(const operation::BLS_Decompress_G1& op, const std::optional<component::G1>& result);
void test(const operation::BLS_Compress_G1& op, const std::optional<component::Bignum>& result);
void test(const operation::BLS_Decompress_G2& op, const std::optional<component::G2>& result);
void test(const operation::BLS_Compress_G2& op, const std::optional<component::G1>& result);
void test(const operation::BLS_G1_Add& op, const std::optional<component::G1>& result);
void test(const operation::BLS_G1_Mul& op, const std::optional<component::G1>& result);
void test(const operation::BLS_G1_IsEq& op, const std::optional<bool>& result);
void test(const operation::BLS_G1_Neg& op, const std::optional<component::G1>& result);
void test(const operation::BLS_G2_Add& op, const std::optional<component::G2>& result);
void test(const operation::BLS_G2_Mul& op, const std::optional<component::G2>& result);
void test(const operation::BLS_G2_IsEq& op, const std::optional<bool>& result);
void test(const operation::BLS_G2_Neg& op, const std::optional<component::G2>& result);
void test(const operation::BLS_G1_MultiExp& op, const std::optional<component::G1>& result);
void test(const operation::Misc& op, const std::optional<Buffer>& result);
void test(const operation::SR25519_Verify& op, const std::optional<bool>& result);

} /* namespace tests */
} /* namespace cryptofuzz */
