#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class num_bigint : public Module {
    public:
        num_bigint(void);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
