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
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
        std::optional<component::ECGDSA_Signature> OpECGDSA_Sign(operation::ECGDSA_Sign& op) override;
        std::optional<component::ECRDSA_Signature> OpECRDSA_Sign(operation::ECRDSA_Sign& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<bool> OpECGDSA_Verify(operation::ECGDSA_Verify& op) override;
        std::optional<bool> OpECRDSA_Verify(operation::ECRDSA_Verify& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Neg(operation::ECC_Point_Neg& op) override;
        std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) override;
        std::optional<bool> OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
