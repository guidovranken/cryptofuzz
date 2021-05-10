#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class chia_bls : public Module {
    public:
        chia_bls(void);
        std::optional<component::BLS_KeyPair> OpBLS_GenerateKeyPair(operation::BLS_GenerateKeyPair& op);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op);
        std::optional<component::G2> OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op);
        std::optional<component::G1> OpBLS_HashToG1(operation::BLS_HashToG1& op);
        std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op);
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op);
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op);
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op);
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op);
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op);
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op);
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op);
        std::optional<component::G1> OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op);
        std::optional<component::G2> OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op);
};

} /* namespace module */
} /* namespace cryptofuzz */
