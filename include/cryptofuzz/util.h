#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/generic.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <string>
#include <utility>

#define CF_CHECK_EQ(expr, res) if ( (expr) != (res) ) { goto end; }
#define CF_CHECK_NE(expr, res) if ( (expr) == (res) ) { goto end; }
#define CF_CHECK_GT(expr, res) if ( (expr) <= (res) ) { goto end; }
#define CF_CHECK_GTE(expr, res) if ( (expr) < (res) ) { goto end; }
#define CF_CHECK_LT(expr, res) if ( (expr) >= (res) ) { goto end; }
#define CF_CHECK_LTE(expr, res) if ( (expr) > (res) ) { goto end; }
#define CF_CHECK_TRUE(expr) if ( !(expr) ) { goto end; }
#define CF_CHECK_FALSE(expr) if ( (expr) ) { goto end; }
#define CF_ASSERT(expr, msg) if ( !(expr) ) { printf("Cryptofuzz assertion failure: %s\n", msg); abort(); }

namespace cryptofuzz {
namespace util {

using Multipart = std::vector< std::pair<const uint8_t*, size_t> >;
const uint8_t* ToInPlace(fuzzing::datasource::Datasource& ds, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& buffer);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const uint8_t* data, const size_t size);
Multipart ToEqualParts(const Buffer& buffer, const size_t partSize);
Multipart ToEqualParts(const uint8_t* data, const size_t size, const size_t partSize);
std::vector<uint8_t> Pkcs7Pad(std::vector<uint8_t> in, const size_t blocksize);
std::optional<std::vector<uint8_t>> Pkcs7Unpad(std::vector<uint8_t> in, const size_t blocksize);
std::string ToString(const Buffer& buffer);
std::string ToString(const bool val);
std::string ToString(const component::Ciphertext& val);
std::string ToString(const component::ECC_PublicKey& val);
std::string ToString(const component::ECC_KeyPair& val);
std::string ToString(const component::ECDSA_Signature& val);
std::string ToString(const component::Bignum& val);
nlohmann::json ToJSON(const Buffer& buffer);
nlohmann::json ToJSON(const bool val);
nlohmann::json ToJSON(const component::Ciphertext& val);
nlohmann::json ToJSON(const component::ECC_PublicKey& val);
nlohmann::json ToJSON(const component::ECC_KeyPair& val);
nlohmann::json ToJSON(const component::ECDSA_Signature& val);
nlohmann::json ToJSON(const component::Bignum& val);
uint8_t* GetNullPtr(fuzzing::datasource::Datasource* ds = nullptr);
uint8_t* malloc(const size_t n);
uint8_t* realloc(void* ptr, const size_t n);
void free(void* ptr);
bool HaveSSE42(void);
void abort(const std::vector<std::string> components);
std::string HexToDec(std::string s);
std::string DecToHex(std::string s);
std::vector<uint8_t> HexToBin(const std::string s);
std::string BinToHex(const uint8_t* data, const size_t size);
std::string BinToHex(const std::vector<uint8_t> data);
std::string BinToDec(const std::vector<uint8_t> data);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::string s);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::vector<uint8_t> data);
std::string SHA1(const std::vector<uint8_t> data);

} /* namespace util */
} /* namespace cryptofuzz */
