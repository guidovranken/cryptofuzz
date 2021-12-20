#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <boost/uuid/sha1.hpp>
#include <optional>

namespace cryptofuzz {
namespace module {

class bc : public Module {
    public:
        bc(void);
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
