#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class secp256k1 : public Module {
    public:
        secp256k1(void);
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
