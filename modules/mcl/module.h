#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class mcl : public Module {
    public:
        mcl(void);
        /*
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op);
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op);
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op);
        */

        std::optional<component::Digest> OpDigest(operation::Digest& op);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op);
        std::optional<component::G2> OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op);
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op);
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op);
        std::optional<bool> OpBLS_Pairing(operation::BLS_Pairing& op);
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op);
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op);
        std::optional<component::G1> OpBLS_HashToG1(operation::BLS_HashToG1& op);
        std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op);
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op);
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op);
        std::optional<bool> OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op);
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op);
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op);
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op);
        std::optional<bool> OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op);
        std::optional<component::G2> OpBLS_G2_Neg(operation::BLS_G2_Neg& op);
        bool SupportsModularBignumCalc(void) const;
};

} /* namespace module */
} /* namespace cryptofuzz */
