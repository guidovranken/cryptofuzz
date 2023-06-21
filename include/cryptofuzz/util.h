#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/generic.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <string>
#include <utility>
#include <setjmp.h>

#define CF_CHECK_EQ(expr, res) if ( (expr) != (res) ) { goto end; }
#define CF_CHECK_NE(expr, res) if ( (expr) == (res) ) { goto end; }
#define CF_CHECK_GT(expr, res) if ( (expr) <= (res) ) { goto end; }
#define CF_CHECK_GTE(expr, res) if ( (expr) < (res) ) { goto end; }
#define CF_CHECK_LT(expr, res) if ( (expr) >= (res) ) { goto end; }
#define CF_CHECK_LTE(expr, res) if ( (expr) > (res) ) { goto end; }
#define CF_CHECK_TRUE(expr) if ( !(expr) ) { goto end; }
#define CF_CHECK_FALSE(expr) if ( (expr) ) { goto end; }
#define CF_ASSERT(expr, msg) if ( !(expr) ) { printf("Cryptofuzz assertion failure: %s\n", msg); ::abort(); }
#define CF_ASSERT_EQ(expr, res) if ( (expr) != (res) ) { printf("Cryptofuzz assertion failure\n"); ::abort(); }
#define CF_ASSERT_EQ_COND(expr, res, cond) if ( (expr) != (res) && !(cond) ) { printf("Cryptofuzz assertion failure\n"); ::abort(); } else goto end;
#define CF_UNREACHABLE() CF_ASSERT(0, "This code is supposed to be unreachable")
#define CF_NORET(expr) {static_assert(std::is_same<decltype(expr), void>::value, "void"); (expr);}

extern "C" {
    extern sigjmp_buf cryptofuzz_jmpbuf;
    extern unsigned char cryptofuzz_longjmp_triggered;
}

#define CF_INSTALL_JMP() do { \
    if( sigsetjmp(cryptofuzz_jmpbuf, 1) && (cryptofuzz_longjmp_triggered == 0) ) { \
        exit(-1); \
    } \
    if( cryptofuzz_longjmp_triggered == 1 ){ \
        goto end; \
    } \
} while(0); \

#define CF_RESTORE_JMP() do { \
    cryptofuzz_longjmp_triggered = 0; \
} while(0); \

namespace cryptofuzz {
namespace util {

using Multipart = std::vector< std::pair<const uint8_t*, size_t> >;
const uint8_t* ToInPlace(fuzzing::datasource::Datasource& ds, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& buffer, const size_t blocksize = 0);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer, const size_t blocksize = 0);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const uint8_t* data, const size_t size, const size_t blocksize = 0);
Multipart ToEqualParts(const Buffer& buffer, const size_t partSize);
Multipart ToEqualParts(const uint8_t* data, const size_t size, const size_t partSize);
std::vector<uint8_t> Pkcs7Pad(std::vector<uint8_t> in, const size_t blocksize);
std::optional<std::vector<uint8_t>> Pkcs7Unpad(std::vector<uint8_t> in, const size_t blocksize);
std::string ToString(const Buffer& buffer);
std::string ToString(const bool val);
std::string ToString(const component::Ciphertext& val);
std::string ToString(const component::ECC_PublicKey& val);
std::string ToString(const component::ECC_KeyPair& val);
std::string ToString(const component::ECCSI_Signature& val);
std::string ToString(const component::ECDSA_Signature& val);
std::string ToString(const component::Bignum& val);
std::string ToString(const component::G2& val);
std::string ToString(const component::BLS_Signature& val);
std::string ToString(const component::BLS_BatchSignature& val);
std::string ToString(const component::BLS_KeyPair& val);
std::string ToString(const component::Fp12& val);
std::string ToString(const component::DSA_Parameters& val);
std::string ToString(const component::DSA_Signature& val);
nlohmann::json ToJSON(const Buffer& buffer);
nlohmann::json ToJSON(const bool val);
nlohmann::json ToJSON(const component::Ciphertext& val);
nlohmann::json ToJSON(const component::ECC_PublicKey& val);
nlohmann::json ToJSON(const component::ECC_KeyPair& val);
nlohmann::json ToJSON(const component::ECCSI_Signature& val);
nlohmann::json ToJSON(const component::ECDSA_Signature& val);
nlohmann::json ToJSON(const component::Bignum& val);
nlohmann::json ToJSON(const component::G2& val);
nlohmann::json ToJSON(const component::BLS_Signature& val);
nlohmann::json ToJSON(const component::BLS_BatchSignature& val);
nlohmann::json ToJSON(const component::BLS_KeyPair& val);
nlohmann::json ToJSON(const component::Fp12& val);
nlohmann::json ToJSON(const component::DSA_Parameters& val);
nlohmann::json ToJSON(const component::DSA_Signature& val);
void SetGlobalDs(fuzzing::datasource::Datasource* ds);
void UnsetGlobalDs(void);
uint8_t* GetNullPtr(fuzzing::datasource::Datasource* ds = nullptr);
uint8_t* malloc(const size_t n);
uint8_t* realloc(void* ptr, const size_t n);
void free(void* ptr);
bool HaveSSE42(void);
void abort(const std::vector<std::string> components);
std::string HexToDec(std::string s);
std::string DecToHex(std::string s, const std::optional<size_t> padTo = std::nullopt);
std::vector<uint8_t> HexToBin(const std::string s);
std::optional<std::vector<uint8_t>> DecToBin(const std::string s, std::optional<size_t> size = std::nullopt);
std::string BinToHex(const uint8_t* data, const size_t size);
std::string BinToHex(const std::vector<uint8_t> data);
std::string BinToDec(const uint8_t* data, const size_t size);
std::string BinToDec(const std::vector<uint8_t> data);
std::optional<std::vector<uint8_t>> ToDER(const std::string A, const std::string B);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::string s);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::vector<uint8_t> data);
std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::string s);
std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::vector<uint8_t> data);
std::string SHA1(const std::vector<uint8_t> data);
void HintBignum(const std::string bn);
void HintBignumPow2(size_t maxSize = 4000);
void HintBignumInt(void);
void HintBignumOpt(const std::optional<std::string> bn);
std::vector<uint8_t> Append(const std::vector<uint8_t> A, const std::vector<uint8_t> B);
std::vector<uint8_t> RemoveLeadingZeroes(std::vector<uint8_t> v);
std::vector<uint8_t> AddLeadingZeroes(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& v);
void AdjustECDSASignature(const uint64_t curveType, component::Bignum& s);
std::string Find_ECC_Y(const std::string& x, const std::string& a, const std::string& b, const std::string& p, const std::string& o, const bool addOrder);
std::array<std::string, 3> ToRandomProjective(fuzzing::datasource::Datasource& ds, const std::string& x, const std::string& y, const uint64_t curveType, const bool jacobian = true, const bool inRange = false);
void MemorySanitizerUnpoison(const void* data, const size_t size);

} /* namespace util */
} /* namespace cryptofuzz */
