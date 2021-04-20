#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class py_ecc : public Module {
    public:
        py_ecc(void);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) override;
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) override;
        std::optional<component::G2> OpBLS_HashToG2(operation::BLS_HashToG2& op) override;
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op) override;
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        std::optional<Buffer> OpMisc(operation::Misc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
