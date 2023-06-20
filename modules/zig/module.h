#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Zig : public Module {
    public:
        Zig(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) override;
        std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) override;
        std::optional<component::Key> OpKDF_ARGON2(operation::KDF_ARGON2& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Sub(operation::ECC_Point_Sub& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
