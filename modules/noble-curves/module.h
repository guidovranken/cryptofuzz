#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class noble_curves : public Module {
    public:
        void* js;
        noble_curves(void);
        ~noble_curves();
        // ECC
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        // BLS
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) override;
        std::optional<component::G1> OpBLS_HashToG1(operation::BLS_HashToG1& op) override;
        std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op) override;
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op) override;
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op) override;
        std::optional<component::Bignum> OpBLS_Compress_G1(operation::BLS_Compress_G1& op) override;
        std::optional<component::G1> OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) override;
        std::optional<component::G1> OpBLS_Compress_G2(operation::BLS_Compress_G2& op) override;
        std::optional<component::G2> OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) override;
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
        std::optional<bool> OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op) override;
        std::optional<component::G2> OpBLS_G2_Neg(operation::BLS_G2_Neg& op) override;
        std::optional<bool> OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) override;
        std::optional<component::G1> OpBLS_Aggregate_G1(operation::BLS_Aggregate_G1& op) override;
        std::optional<component::G2> OpBLS_Aggregate_G2(operation::BLS_Aggregate_G2& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
