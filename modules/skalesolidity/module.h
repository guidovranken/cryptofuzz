#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"
#include <optional>

namespace cryptofuzz {
namespace module {

class SkaleSolidity : public Module {
    public:
        SkaleSolidity(void);
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) override;
        std::optional<bool> OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Double(operation::BLS_G2_Add& op);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        std::optional<component::Fp2> OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) override;
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
