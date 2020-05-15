#include "tests.h"
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace tests {

template <class ResultType, class OperationType>
void verifyKeySize(const OperationType& op, const ResultType& result) {
    if ( result != std::nullopt && op.keySize != result->GetSize() ) {
        /* TODO include module name in abort message */
        util::abort({op.Name(), "invalid keySize"});
    }
}

void test(const operation::Digest& op, const std::optional<component::Digest>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    const auto expectedSize = repository::DigestSize(op.digestType.Get());

    if ( expectedSize == std::nullopt ) {
        return;
    }

    if ( result->GetSize() != *expectedSize ) {
        printf("Expected vs actual digest size: %zu / %zu\n", *expectedSize, result->GetSize());
        abort();
    }
}

void test(const operation::HMAC& op, const std::optional<component::MAC>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    const auto expectedSize = repository::DigestSize(op.digestType.Get());

    if ( expectedSize == std::nullopt ) {
        return;
    }

    if ( result->GetSize() != *expectedSize ) {
        printf("Expected vs actual digest size: %zu / %zu\n", *expectedSize, result->GetSize());
        abort();
    }
}

static void test_ChaCha20_Poly1305_IV(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    using fuzzing::datasource::ID;

    /*
     * OpenSSL CVE-2019-1543
     * https://www.openssl.org/news/secadv/20190306.txt
     */

    if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20_POLY1305") ) {
        return;
    }

    if ( result == std::nullopt ) {
        return;
    }

    if ( op.cipher.iv.GetSize() > 12 ) {
        abort();
    }
}

static void test_AES_CCM_Wycheproof(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    bool fail = false;

    if ( result == std::nullopt ) {
        return;
    }

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
            break;
        default:
            return;
    }

    if ( op.cipher.iv.GetSize() < 7 || op.cipher.iv.GetSize() > 13 ) {
        printf("AES CCM: Invalid IV size\n");
        fail = true;
    }

    if ( result->tag != std::nullopt ) {
        static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};

        if ( std::find(validTagSizes.begin(), validTagSizes.end(), result->tag->GetSize()) == validTagSizes.end() ) {
            printf("AES CCM: Invalid tag size\n");
            fail = true;
        }
    }

    if ( fail == true ) {
        printf("AES CCM tests based on Wycheproof: https://github.com/google/wycheproof/blob/4672ff74d68766e7785c2cac4c597effccef2c5c/testvectors/aes_ccm_test.json#L11\n");
        abort();
    }
}

static void test_AES_GCM_Wycheproof(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    bool fail = false;

    if ( result == std::nullopt ) {
        return;
    }

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
            break;
        default:
            return;
    }

    if ( op.cipher.iv.GetSize() == 0 ) {
        printf("AES GCM: Invalid IV size\n");
        fail = true;
    }

    if ( fail == true ) {
        printf("AES GCM tests based on Wycheproof: https://github.com/google/wycheproof/blob/4672ff74d68766e7785c2cac4c597effccef2c5c/testvectors/aes_gcm_test.json#L13\n");
        abort();
    }
}

void test(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    test_ChaCha20_Poly1305_IV(op, result);
    test_AES_CCM_Wycheproof(op, result);
    test_AES_GCM_Wycheproof(op, result);
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
    verifyKeySize(op, result);
}

static void test_HKDF_OutputSize(const operation::KDF_HKDF& op, const std::optional<component::Key>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    const auto expectedSize = repository::DigestSize(op.digestType.Get());

    if ( expectedSize == std::nullopt ) {
        return;
    }

    const size_t maxOutputSize = 255 * *expectedSize;

    if ( result->GetSize() > maxOutputSize ) {
        printf("The output size of HKDF (%zu) is more than 255 * the size of the hash digest (%zu)\n", result->GetSize(), maxOutputSize);
        abort();
    }
}

void test(const operation::KDF_HKDF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);

    test_HKDF_OutputSize(op, result);
}

void test(const operation::KDF_TLS1_PRF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF1& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_PBKDF2& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_ARGON2& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_SSH& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_X963& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_BCRYPT& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::KDF_SP_800_108& op, const std::optional<component::Key>& result) {
    verifyKeySize(op, result);
}

void test(const operation::Sign& op, const std::optional<component::Signature>& result) {
    (void)op;
    (void)result;
}

void test(const operation::Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_PrivateToPublic& op, const std::optional<component::ECC_PublicKey>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECC_GenerateKeyPair& op, const std::optional<component::ECC_KeyPair>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECDSA_Sign& op, const std::optional<component::ECDSA_Signature>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECDSA_Verify& op, const std::optional<bool>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECDH_Derive& op, const std::optional<component::Secret>& result) {
    (void)op;
    (void)result;
}

void test(const operation::BignumCalc& op, const std::optional<component::Bignum>& result) {
    (void)op;
    (void)result;
}

} /* namespace tests */
} /* namespace cryptofuzz */
