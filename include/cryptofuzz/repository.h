#pragma once

#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace repository {

template <uint64_t id> constexpr uint64_t Digest(void);
template <uint64_t id> constexpr uint64_t Cipher(void);
template <uint64_t id> constexpr bool IsCBC(void);
template <uint64_t id> constexpr bool IsCCM(void);
template <uint64_t id> constexpr bool IsCFB(void);
template <uint64_t id> constexpr bool IsCTR(void);
template <uint64_t id> constexpr bool IsECB(void);
template <uint64_t id> constexpr bool IsOCB(void);
template <uint64_t id> constexpr bool IsOFB(void);
template <uint64_t id> constexpr bool IsXTS(void);
template <uint64_t id> constexpr bool IsAEAD(void);

} /* namespace repository */
} /* namespace cryptofuzz */

#define CF_CIPHER(s) cryptofuzz::repository::Cipher<fuzzing::datasource::ID("Cryptofuzz/Cipher/" s)>()
#define CF_DIGEST(s) cryptofuzz::repository::Digest<fuzzing::datasource::ID("Cryptofuzz/Digest/" s)>()
