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
bool IsAES(const uint64_t id);
std::string DigestToString(const uint64_t id);
std::string CipherToString(const uint64_t id);
std::string ECC_CurveToString(const uint64_t id);
std::string CalcOpToString(const uint64_t id);
std::optional<size_t> DigestSize(const uint64_t id);

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
constexpr long moduleIndex(void) {
    constexpr long index = LUTCheck(id, ModuleLUT, sizeof(ModuleLUT) / sizeof(ModuleLUT[0]));
    static_assert(-1 != index, "Not a valid module");
    return index;
}

template <uint64_t id>
constexpr uint64_t Module(void) {
    (void)moduleIndex<id>();
    return id;
}

template <uint64_t id>
constexpr long operationIndex(void) {
    constexpr long index = LUTCheck(id, OperationLUT, sizeof(OperationLUT) / sizeof(OperationLUT[0]));
    static_assert(-1 != index, "Not a valid operation");
    return index;
}

template <uint64_t id>
constexpr uint64_t Operation(void) {
    (void)operationIndex<id>();
    return id;
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

template <uint64_t id>
constexpr long ecc_CurveIndex(void) {
    constexpr long index = LUTCheck(id, ECC_CurveLUT, sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0]));
    static_assert(-1 != index, "Not a valid ECC curve");
    return index;
}

template <uint64_t id>
constexpr uint64_t ECC_Curve(void) {
    (void)ecc_CurveIndex<id>();
    return id;
}

template <uint64_t id>
constexpr long calcOpIndex(void) {
    constexpr long index = LUTCheck(id, CalcOpLUT, sizeof(CalcOpLUT) / sizeof(CalcOpLUT[0]));
    static_assert(-1 != index, "Not a valid calculation operation");
    return index;
}

template <uint64_t id>
constexpr uint64_t CalcOp(void) {
    (void)calcOpIndex<id>();
    return id;
}

} /* namespace repository */
} /* namespace cryptofuzz */

#define CF_CIPHER(s) cryptofuzz::repository::Cipher<fuzzing::datasource::ID("Cryptofuzz/Cipher/" s)>()
#define CF_DIGEST(s) cryptofuzz::repository::Digest<fuzzing::datasource::ID("Cryptofuzz/Digest/" s)>()
#define CF_MODULE(s) cryptofuzz::repository::Module<fuzzing::datasource::ID("Cryptofuzz/Module/" s)>()
#define CF_OPERATION(s) cryptofuzz::repository::Operation<fuzzing::datasource::ID("Cryptofuzz/Operation/" s)>()
#define CF_ECC_CURVE(s) cryptofuzz::repository::ECC_Curve<fuzzing::datasource::ID("Cryptofuzz/ECC_Curve/" s)>()
#define CF_CALCOP(s) cryptofuzz::repository::CalcOp<fuzzing::datasource::ID("Cryptofuzz/CalcOp/" s)>()
