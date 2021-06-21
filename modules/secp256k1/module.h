#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class secp256k1 : public Module {
    public:
        secp256k1(void);
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::ECC_PublicKey> OpECDSA_Recover(operation::ECDSA_Recover& op) override;
        std::optional<component::Schnorr_Signature> OpSchnorr_Sign(operation::Schnorr_Sign& op) override;
        std::optional<bool> OpSchnorr_Verify(operation::Schnorr_Verify& op) override;
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
