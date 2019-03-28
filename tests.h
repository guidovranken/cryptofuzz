#pragma once

#include <cryptofuzz/operations.h>
#include <cryptofuzz/components.h>

namespace cryptofuzz {
namespace tests {

void test(const operation::Digest& op, const std::optional<component::Digest>& result);
void test(const operation::HMAC& op, const std::optional<component::MAC>& result);
void test(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result);
void test(const operation::SymmetricDecrypt& op, const std::optional<component::Cleartext>& result);
void test(const operation::CMAC& op, const std::optional<component::MAC>& result);
void test(const operation::KDF_SCRYPT& op, const std::optional<component::Key>& result);
void test(const operation::KDF_HKDF& op, const std::optional<component::Key>& result);
void test(const operation::KDF_TLS1_PRF& op, const std::optional<component::Key>& result);
void test(const operation::KDF_PBKDF2& op, const std::optional<component::Key>& result);
void test(const operation::Sign& op, const std::optional<component::Signature>& result);
void test(const operation::Verify& op, const std::optional<bool>& result);

} /* namespace tests */
} /* namespace cryptofuzz */
