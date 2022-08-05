#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class wide_integer : public Module {
    public:
        wide_integer(void);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
