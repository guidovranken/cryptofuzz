#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class libecc : public Module {
    public:
        libecc(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<component::ECGDSA_Signature> OpECGDSA_Sign(operation::ECGDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<bool> OpECGDSA_Verify(operation::ECGDSA_Verify& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
