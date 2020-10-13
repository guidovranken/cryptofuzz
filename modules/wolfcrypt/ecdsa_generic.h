#pragma once

#include <cryptofuzz/operations.h>
#include <optional>

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Generic(operation::ECC_PrivateToPublic& op);
std::optional<bool> OpECDSA_Verify_Generic(operation::ECDSA_Verify& op);
std::optional<component::ECDSA_Signature> OpECDSA_Sign_Generic(operation::ECDSA_Sign& op);

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
