#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>

namespace cryptofuzz {
namespace repository {

#include "repository_tbl.h"

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
