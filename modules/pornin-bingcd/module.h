#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <boost/uuid/sha1.hpp>
#include <optional>

namespace cryptofuzz {
namespace module {

class Pornin_BinGCD : public Module {
    public:
        Pornin_BinGCD(void);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

} /* namespace module */
} /* namespace cryptofuzz */
