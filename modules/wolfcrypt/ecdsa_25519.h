#pragma once

#include <cryptofuzz/operations.h>
#include <optional>

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Curve25519(operation::ECC_PrivateToPublic& op);
std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Ed25519(operation::ECC_PrivateToPublic& op);
std::optional<bool> OpECC_ValidatePubkey_Ed25519(operation::ECC_ValidatePubkey& op);
std::optional<bool> OpECC_ValidatePubkey_Curve25519(operation::ECC_ValidatePubkey& op);
std::optional<component::ECDSA_Signature> OpECDSA_Sign_ed25519(operation::ECDSA_Sign& op);
std::optional<bool> OpECDSA_Verify_ed25519(operation::ECDSA_Verify& op);

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
