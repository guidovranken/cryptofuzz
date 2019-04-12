#pragma once

#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace repository {

bool IsCBC(const uint64_t id);
bool IsCCM(const uint64_t id);
bool IsCFB(const uint64_t id);
bool IsCTR(const uint64_t id);
bool IsECB(const uint64_t id);
bool IsGCM(const uint64_t id);
bool IsOCB(const uint64_t id);
bool IsOFB(const uint64_t id);
bool IsXTS(const uint64_t id);
bool IsAEAD(const uint64_t id);
bool IsWRAP(const uint64_t id);
std::string DigestToString(const uint64_t id);
std::string CipherToString(const uint64_t id);

#include "../../repository_tbl.h"

template <typename LUT>
inline constexpr long LUTCheck(const uint64_t id, const LUT* lut, const size_t lutSize) noexcept {
    for (size_t i = 0; i < lutSize; i++) {
        if ( lut[i].id == id ) {
            return i;
        }
    }

    return -1;
}

template <uint64_t id>
constexpr long digestIndex(void) {
    constexpr long index = LUTCheck(id, DigestLUT, sizeof(DigestLUT) / sizeof(DigestLUT[0]));
    static_assert(-1 != index, "Not a valid digest");
    return index;
}

template <uint64_t id>
constexpr uint64_t Digest(void) {
    (void)digestIndex<id>();
    return id;
}

template <uint64_t id>
constexpr long cipherIndex(void) {
    constexpr long index = LUTCheck(id, CipherLUT, sizeof(CipherLUT) / sizeof(CipherLUT[0]));
    static_assert(-1 != index, "Not a valid cipher");
    return index;
}

template <uint64_t id>
constexpr uint64_t Cipher(void) {
    (void)cipherIndex<id>();
    return id;
}

} /* namespace repository */
} /* namespace cryptofuzz */

#define CF_CIPHER(s) cryptofuzz::repository::Cipher<fuzzing::datasource::ID("Cryptofuzz/Cipher/" s)>()
#define CF_DIGEST(s) cryptofuzz::repository::Digest<fuzzing::datasource::ID("Cryptofuzz/Digest/" s)>()
