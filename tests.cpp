#include "tests.h"
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>

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

static void test_XChaCha20_Poly1305_IV(const operation::SymmetricEncrypt& op, const std::optional<component::Ciphertext>& result) {
    using fuzzing::datasource::ID;

    if ( op.cipher.cipherType.Get() != CF_CIPHER("XCHACHA20_POLY1305") ) {
        return;
    }

    if ( result == std::nullopt ) {
        return;
    }

    if ( op.cipher.iv.GetSize() != 24 ) {
        printf("XChaCha20-Poly1305 succeeded with an IV of %zu bytes large, but only IVs of 24 bytes are valid\n", op.cipher.iv.GetSize());
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
    test_XChaCha20_Poly1305_IV(op, result);
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

static void test_ECC_PrivateKey(const uint64_t curveID, const std::string priv) {
    /* Disabled until all modules comply by default */
    return;

    /* Private key may be 0 with these curves */
    if ( curveID == CF_ECC_CURVE("ed448") ) return;
    if ( curveID == CF_ECC_CURVE("ed25519") ) return;
    if ( curveID == CF_ECC_CURVE("x25519") ) return;
    if ( curveID == CF_ECC_CURVE("x448") ) return;

    if ( priv == "0" ) {
        std::cout << "0 is an invalid elliptic curve private key" << std::endl;
        ::abort();
    }
}


void test(const operation::ECC_PrivateToPublic& op, const std::optional<component::ECC_PublicKey>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());
    }
}

void test(const operation::ECC_GenerateKeyPair& op, const std::optional<component::ECC_KeyPair>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), result->priv.ToTrimmedString());
    }
}

static void test_ECDSA_Signature(const uint64_t curveID, const std::string R, const std::string S) {
    if ( curveID == CF_ECC_CURVE("ed448") ) return;
    if ( curveID == CF_ECC_CURVE("ed25519") ) return;
    if ( curveID == CF_ECC_CURVE("x25519") ) return;
    if ( curveID == CF_ECC_CURVE("x448") ) return;

    boost::multiprecision::cpp_int r(R);
    boost::multiprecision::cpp_int s(S);
    if ( r < 1 ) {
        std::cout << "ECDSA signature invalid: R < 1" << std::endl;
        ::abort();
    }
    if ( s < 1 ) {
        std::cout << "ECDSA signature invalid: R < 1" << std::endl;
        ::abort();
    }
}

void test(const operation::ECDSA_Sign& op, const std::optional<component::ECDSA_Signature>& result) {
    if ( result != std::nullopt ) {
        test_ECC_PrivateKey(op.curveType.Get(), op.priv.ToTrimmedString());

        test_ECDSA_Signature(op.curveType.Get(),
                result->signature.first.ToTrimmedString(),
                result->signature.second.ToTrimmedString());
    }
}

void test(const operation::ECDSA_Verify& op, const std::optional<bool>& result) {
    if ( result != std::nullopt && *result == true ) {
        test_ECDSA_Signature(op.curveType.Get(),
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString());
    }
}

void test(const operation::ECDH_Derive& op, const std::optional<component::Secret>& result) {
    (void)op;
    (void)result;
}

void test(const operation::ECIES_Encrypt& op, const std::optional<component::Ciphertext>& result) {
    /* TODO check minimum size? */
    (void)op;
    (void)result;
}

void test(const operation::DH_GenerateKeyPair& op, const std::optional<component::DH_KeyPair>& result) {
    (void)op;
    (void)result;
}

void test(const operation::DH_Derive& op, const std::optional<component::Bignum>& result) {
    (void)op;
    (void)result;
}

namespace BignumCalc {
    static void Abort(const std::string& message, const std::string& opStr) {
        std::cout << "BignumCalc ( " << opStr << " ): " << message << std::endl;
        ::abort();
    }
    static void AssertBinary(const component::Bignum& result, const std::string& opStr) {
        const auto resultStr = result.ToTrimmedString();
        if ( !(resultStr == "0" || resultStr == "1") ) {
            Abort("Result must be 0 or 1", opStr);
        }
    }
    static void AssertTertiary(const component::Bignum& result, const std::string& opStr) {
        const auto resultStr = result.ToTrimmedString();
        if ( !(resultStr == "0" || resultStr == "1" || resultStr == "-1") ) {
            Abort("Result must be 0 or 1 or -1", opStr);
        }
    }
    static bool IsEqual(const component::Bignum& A, const component::Bignum& B) {
        return A.ToTrimmedString() == B.ToTrimmedString();
    }
    static bool IsZero(const component::Bignum& A) {
        return A.ToTrimmedString() == "0";
    }
    static bool SmallerThan(const component::Bignum& A, const component::Bignum& B) {
        return A.ToTrimmedString().size() < B.ToTrimmedString().size();
    }
    static bool LargerThan(const component::Bignum& A, const component::Bignum& B) {
        return A.ToTrimmedString().size() > B.ToTrimmedString().size();
    }
    static void AssertModResult(const component::Bignum& result, const component::Bignum& mod, const std::string& opStr) {
        if ( LargerThan(result, mod) ) {
            Abort("Result is larger than modulo", opStr);
        }
    }
    static void AssertNotSmallerThan(const component::Bignum& result, const component::Bignum& A, const std::string& opStr) {
        if ( SmallerThan(result, A) ) {
            Abort("Result is larger than the input", opStr);
        }
    }
    static void AssertNotLargerThan(const component::Bignum& result, const component::Bignum& A, const std::string& opStr) {
        if ( LargerThan(result, A) ) {
            Abort("Result is larger than the input", opStr);
        }
    }
}

void test(const operation::BignumCalc& op, const std::optional<component::Bignum>& result) {
    if ( result == std::nullopt ) {
        return;
    }

    using namespace BignumCalc;

    const auto calcOp = op.calcOp.Get();

    switch ( calcOp ) {
        case    CF_CALCOP("Add(A,B)"):
            if (    SmallerThan(*result, op.bn0) ||
                    SmallerThan(*result, op.bn1) ) {
                Abort("Result is smaller than its operands", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            if ( IsZero(op.bn1) ) {
                Abort("Division by zero should not produce a result", repository::CalcOpToString(calcOp));
            }

            if ( LargerThan(*result, op.bn0) ) {
                Abort("Result is larger than the dividend", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            if ( IsZero(op.bn0) || IsZero(op.bn1) ) {
                if ( !IsZero(*result) ) {
                    Abort("Result of Mul with zero operand is not zero", repository::CalcOpToString(calcOp));
                }
            }
            break;
        case    CF_CALCOP("Mod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "Mod");
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "ExpMod");
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "AddMod");
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "SubMod");
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "MulMod");
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "SqrMod");
            break;
        case    CF_CALCOP("SqrtMod(A,B)"):
            BignumCalc::AssertModResult(*result, op.bn1, "SqrtMod");
            break;
        case    CF_CALCOP("ModLShift(A,B,C)"):
            BignumCalc::AssertModResult(*result, op.bn2, "ModLShift");
            break;
        case    CF_CALCOP("Bit(A,B)"):
            BignumCalc::AssertBinary(*result, "Bit");
            break;
        case    CF_CALCOP("IsCoprime(A,B)"):
            BignumCalc::AssertBinary(*result, "IsCoprime");
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            BignumCalc::AssertBinary(*result, "IsEq");
            break;
        case    CF_CALCOP("IsEven(A)"):
            BignumCalc::AssertBinary(*result, "IsEven");
            break;
        case    CF_CALCOP("IsOdd(A)"):
            BignumCalc::AssertBinary(*result, "IsOdd");
            break;
        case    CF_CALCOP("IsOne(A)"):
            BignumCalc::AssertBinary(*result, "IsOne");
            break;
        case    CF_CALCOP("IsPow2(A)"):
            BignumCalc::AssertBinary(*result, "IsPow2");
            break;
        case    CF_CALCOP("IsPrime(A)"):
            BignumCalc::AssertBinary(*result, "IsPrime");
            break;
        case    CF_CALCOP("IsZero(A)"):
            BignumCalc::AssertBinary(*result, "IsZero");
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            BignumCalc::AssertTertiary(*result, "Cmp");
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            BignumCalc::AssertTertiary(*result, "CmpAbs");
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            BignumCalc::AssertTertiary(*result, "Jacobi");
            break;
        case    CF_CALCOP("Sqr(A)"):
            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("RShift(A,B)"):
            if ( IsZero(op.bn0) || IsZero(op.bn1) ) {
                if ( op.bn0.ToTrimmedString() != result->ToTrimmedString() ) {
                    Abort("Zero operand should not alter input", repository::CalcOpToString(calcOp));
                }
            }

            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("LShift1(A)"):
            if ( IsZero(op.bn0) ) {
                if ( op.bn0.ToTrimmedString() != result->ToTrimmedString() ) {
                    Abort("Zero input should remain zero", repository::CalcOpToString(calcOp));
                }
            }

            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            AssertNotSmallerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Sqrt(A)"):
            AssertNotLargerThan(*result, op.bn0, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("MulAdd(A,B,C)"):
            AssertNotSmallerThan(*result, op.bn2, repository::CalcOpToString(calcOp));
            break;
        case    CF_CALCOP("Min(A,B)"):
        case    CF_CALCOP("Max(A,B)"):
            if ( !IsEqual(*result, op.bn0) && !IsEqual(*result, op.bn1) ) {
                Abort("Result is not an operand", repository::CalcOpToString(calcOp));
            }
            break;
        case    CF_CALCOP("Mask(A,B)"):
            if ( LargerThan(*result, op.bn0) ) {
                Abort("Result is larger than input", repository::CalcOpToString(calcOp));
            }
            break;
    }
}

} /* namespace tests */
} /* namespace cryptofuzz */
