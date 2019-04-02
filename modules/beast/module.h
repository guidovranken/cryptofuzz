#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>
#include <boost/beast/core/detail/sha1.hpp>

namespace cryptofuzz {
namespace module {

class Beast : public Module {
    public:
        Beast(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
