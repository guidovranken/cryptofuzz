#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class BouncyCastle : public Module {
    public:
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        BouncyCastle(void);
};

} /* namespace module */
} /* namespace cryptofuzz */
