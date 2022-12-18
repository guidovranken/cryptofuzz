#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"
#include <optional>

namespace cryptofuzz {
namespace module {

class kilic_bls12_381 : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        kilic_bls12_381(void);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) override;
        std::optional<component::G2> OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) override;
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
