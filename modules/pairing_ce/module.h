#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class pairing_ce : public Module {
    public:
        pairing_ce(void);
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
