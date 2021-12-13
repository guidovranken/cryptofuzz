#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class rust_uint : public Module {
    public:
        rust_uint(void);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
