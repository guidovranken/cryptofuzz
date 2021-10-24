#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class nimcrypto : public Module {
    public:
        nimcrypto(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
