#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <boost/uuid/sha1.hpp>
#include <optional>

namespace cryptofuzz {
namespace module {

class Boost : public Module {
    public:
        Boost(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
