#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class blst : public Module {
    public:
        blst(void);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) override;
        std::optional<component::G2> OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) override;
        std::optional<component::G1> OpBLS_HashToG1(operation::BLS_HashToG1& op) override;
        std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op) override;
        std::optional<component::G1> OpBLS_MapToG1(operation::BLS_MapToG1& op) override;
        std::optional<component::G2> OpBLS_MapToG2(operation::BLS_MapToG2& op) override;
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op) override;
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op) override;
        std::optional<bool> OpBLS_BatchVerify(operation::BLS_BatchVerify& op) override;
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) override;
        std::optional<component::BLS_KeyPair> OpBLS_GenerateKeyPair(operation::BLS_GenerateKeyPair& op) override;
        std::optional<component::G1> OpBLS_Aggregate_G1(operation::BLS_Aggregate_G1& op) override;
        std::optional<component::G2> OpBLS_Aggregate_G2(operation::BLS_Aggregate_G2& op) override;
        std::optional<component::Fp12> OpBLS_Pairing(operation::BLS_Pairing& op) override;
        std::optional<component::Fp12> OpBLS_MillerLoop(operation::BLS_MillerLoop& op) override;
        std::optional<component::Fp12> OpBLS_FinalExp(operation::BLS_FinalExp& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        std::optional<component::Fp2> OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) override;
        std::optional<component::Fp12> OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) override;
        std::optional<component::G1> OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) override;
        std::optional<component::Bignum> OpBLS_Compress_G1(operation::BLS_Compress_G1& op) override;
        std::optional<component::G2> OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) override;
        std::optional<component::G1> OpBLS_Compress_G2(operation::BLS_Compress_G2& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<bool> OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op) override;
        std::optional<bool> OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) override;
        std::optional<component::G2> OpBLS_G2_Neg(operation::BLS_G2_Neg& op) override;
        std::optional<component::G1> OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) override;
        std::optional<Buffer> OpMisc(operation::Misc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
