#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class schnorrkel : public Module {
    public:
        schnorrkel(void);
        std::optional<bool> OpSR25519_Verify(operation::SR25519_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
