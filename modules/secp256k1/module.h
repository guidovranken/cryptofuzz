#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class secp256k1 : public Module {
    public:
        secp256k1(void);
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::ECC_PublicKey> OpECDSA_Recover(operation::ECDSA_Recover& op) override;
#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
        std::optional<component::Schnorr_Signature> OpSchnorr_Sign(operation::Schnorr_Sign& op) override;
        std::optional<bool> OpSchnorr_Verify(operation::Schnorr_Verify& op) override;
#endif
#if !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
#endif
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
