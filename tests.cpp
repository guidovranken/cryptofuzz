#include "tests.h"
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace tests {

void test(const operation::Digest& op, const std::optional<component::Digest>& result) {
    (void)op;
    (void)result;
}

void test(const operation::HMAC& op, const std::optional<component::MAC>& result) {
    (void)op;
    (void)result;
}

static void test_ChaCha20_Poly1305_IV(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    using fuzzing::datasource::ID;

    /*
     * OpenSSL CVE-2019-1543
     * https://www.openssl.org/news/secadv/20190306.txt
     */

    if ( op.cipher.cipherType.Get() != ID("Cryptofuzz/Cipher/CHACHA20_POLY1305") ) {
        return;
    }

    if ( result == std::nullopt ) {
        return;
    }

    if ( op.cipher.iv.GetSize() > 12 ) {
        abort();
    }
}

void test(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    test_ChaCha20_Poly1305_IV(op, result);
}

void test(const operation::SymmetricDecrypt& op, const std::optional<component::Cleartext>& result) {
    (void)op;
    (void)result;
}

void test(const operation::CMAC& op, const std::optional<component::MAC>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_SCRYPT& op, const std::optional<component::Key>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_HKDF& op, const std::optional<component::Key>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_TLS1_PRF& op, const std::optional<component::Key>& result) {
    (void)op;
    (void)result;
}

void test(const operation::KDF_PBKDF2& op, const std::optional<component::Key>& result) {
    (void)op;
    (void)result;
}

void test(const operation::Sign& op, const std::optional<component::Signature>& result) {
    (void)op;
    (void)result;
}

void test(const operation::Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

} /* namespace tests */
} /* namespace cryptofuzz */
