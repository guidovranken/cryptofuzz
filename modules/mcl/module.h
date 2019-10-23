#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class mcl : public Module {
    public:
        mcl(void);
        /*
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op);
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op);
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op);
        */

        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op);
        std::optional<component::BLS_Signature> OpBLS_Sign(operation::BLS_Sign& op);
        std::optional<bool> OpBLS_Verify(operation::BLS_Verify& op);
};

} /* namespace module */
} /* namespace cryptofuzz */
