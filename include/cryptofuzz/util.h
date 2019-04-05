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

namespace cryptofuzz {
namespace util {

size_t GetDigestSize(const component::DigestType digestType);
std::string DigestIDToString(const component::DigestType digestType);
std::string SymmetricCipherIDToString(const component::SymmetricCipherType cipherType);
using Multipart = std::vector< std::pair<const uint8_t*, size_t> >;
Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer);
std::string HexDump(const void *_data, const size_t len, const std::string description = "");
std::string HexDump(std::vector<uint8_t> data, const std::string description = "");
std::string ToString(const Buffer& buffer);
std::string ToString(const bool val);
uint8_t* GetNullPtr(void);
uint8_t* malloc(const size_t n);
uint8_t* realloc(void* ptr, const size_t n);
void free(void* ptr);

} /* namespace util */
} /* namespace cryptofuzz */
