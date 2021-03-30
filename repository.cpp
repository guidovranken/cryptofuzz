#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include <map>
#include <cstdint>
#include <string>
#include "repository_map.h"

namespace cryptofuzz {
namespace repository {

bool IsCBC(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CBC;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsCCM(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CCM;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsCFB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CFB;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsCTR(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CTR;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsECB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).ECB;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsGCM(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).GCM;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsOCB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).OCB;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsOFB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).OFB;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsXTS(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).XTS;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsAEAD(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).AEAD;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsWRAP(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).WRAP;
    } catch ( std::out_of_range ) {
        return false;
    }
}

bool IsAES(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).AES;
    } catch ( std::out_of_range ) {
        return false;
    }
}

std::string DigestToString(const uint64_t id) {
    try {
        return DigestLUTMap.at(id).name;
    } catch ( std::out_of_range ) {
        return "(unknown)";
    }
}

std::optional<uint64_t> DigestFromString(const std::string& s) {
    for (const auto& curve : DigestLUTMap) {
        if ( s == curve.second.name ) {
            return curve.first;
        }
    }

    return std::nullopt;
}

std::string CipherToString(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).name;
    } catch ( std::out_of_range ) {
        return "(unknown)";
    }
}

std::string ECC_CurveToString(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).name;
    } catch ( std::out_of_range ) {
        return "(unknown)";
    }
}

std::optional<uint64_t> ECC_CurveFromString(const std::string& s) {
    for (const auto& curve : ECC_CurveLUTMap) {
        if ( s == curve.second.name ) {
            return curve.first;
        }
    }

    return std::nullopt;
}

std::optional<size_t> ECC_CurveToBits(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).bits;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToPrime(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).prime;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToA(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).a;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToB(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).b;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToX(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).x;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToY(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).y;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToOrderMin1(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).order_min_1;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToOrder(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).order;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

std::string CalcOpToString(const uint64_t id) {
    try {
        return CalcOpLUTMap.at(id).name;
    } catch ( std::out_of_range ) {
        return "(unknown)";
    }
}

std::optional<size_t> DigestSize(const uint64_t id) {
    try {
        return DigestLUTMap.at(id).size;
    } catch ( std::out_of_range ) {
        return std::nullopt;
    }
}

} /* namespace repository */
} /* namespace cryptofuzz */
