#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <boost/uuid/sha1.hpp>
#include <optional>

namespace cryptofuzz {
namespace module {

class Starkware : public Module {
    public:
        Starkware(void);
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
