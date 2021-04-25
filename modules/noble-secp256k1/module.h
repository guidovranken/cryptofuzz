#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class noble_secp256k1 : public Module {
    public:
        void* js;
        noble_secp256k1(void);
        ~noble_secp256k1();
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
