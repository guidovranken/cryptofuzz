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
