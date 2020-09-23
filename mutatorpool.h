#pragma once

#include <array>
#include <string>
#include <cstdint>

typedef struct {
    uint64_t curveID;
    std::string priv;
} CurvePrivkey_Pair;

extern std::array<CurvePrivkey_Pair, 64> Pool_CurvePrivkey;

typedef struct {
    uint64_t curveID;
    std::string privkey;
    std::string pub_x;
    std::string pub_y;
} CurveKeypair_Pair;

extern std::array<CurveKeypair_Pair, 64> Pool_CurveKeypair;

typedef struct {
    uint64_t curveID;
    std::string sig_r;
    std::string sig_y;
} CurveECDSASignature_Pair;

extern std::array<CurveECDSASignature_Pair, 64> Pool_CurveECDSASignature;

extern std::array<std::string, 64> Pool_Bignum;
