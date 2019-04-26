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

using Multipart = std::vector< std::pair<const uint8_t*, size_t> >;
Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer);
std::string ToString(const Buffer& buffer);
std::string ToString(const bool val);
std::string ToString(const component::Ciphertext& val);
uint8_t* GetNullPtr(void);
uint8_t* malloc(const size_t n);
uint8_t* realloc(void* ptr, const size_t n);
void free(void* ptr);

} /* namespace util */
} /* namespace cryptofuzz */
