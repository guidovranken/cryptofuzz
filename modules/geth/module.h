#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Geth : public Module {
    public:
        Geth(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<bool> OpBLS_BatchVerify(operation::BLS_BatchVerify& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
