#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include "repository_map.h"

namespace cryptofuzz {
namespace repository {

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

} /* namespace repository */
} /* namespace cryptofuzz */
