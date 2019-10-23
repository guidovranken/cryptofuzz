#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class chia_bls : public Module {
    public:
        chia_bls(void);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op);
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op);
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op);
};

} /* namespace module */
} /* namespace cryptofuzz */
