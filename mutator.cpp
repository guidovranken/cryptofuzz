#include <cstdint>
#include <array>
#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/options.h>
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/lexical_cast.hpp>
#include "config.h"
#include "repository_tbl.h"
#include "numbers.h"
#include "mutatorpool.h"
#include "third_party/json/json.hpp"

uint32_t PRNG(void)
{
    static uint32_t nSeed = 5323;
    nSeed = (8253729 * nSeed + 2396403);
    return nSeed  % 32767;
}

static std::vector<size_t> SplitLength(size_t left, const size_t numParts) {
    std::vector<size_t> lengths;
    for (size_t i = 0; i < numParts; i++) {
        const auto cur = PRNG() % (left+1);
        lengths.push_back(cur);
        left -= cur;
    }

    std::vector<size_t> lengths_randomized;
    for (size_t i = 0; i < numParts; i++) {
        const auto cur = lengths.begin() + PRNG() % (lengths.size());
        lengths_randomized.push_back(*cur);
        lengths.erase(cur);
    }

    return lengths_randomized;
}

static bool getBool(void) {
    return PRNG() % 2 == 0;
}

static size_t getDefaultSize(void) {
    static const std::array defaultSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};

    return defaultSizes[PRNG() % defaultSizes.size()];
}

static std::string getBuffer(size_t size, const bool alternativeSize = false) {
    static const std::array<std::string, 256> hex = {
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
        "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"};

    if ( alternativeSize == true ) {
        if ( getBool() ) {
            const auto newSize = getDefaultSize();
            if ( newSize < size ) {
                size = newSize;
            }
        }
    }

    std::string ret;

    for (size_t i = 0; i < size; i++) {
        ret += hex[PRNG() % 256];
    }

    return ret;
}

static std::vector<uint8_t> getBufferBin(const size_t size) {
    std::vector<uint8_t> ret(size);

    for (size_t i = 0; i < size; i++) {
        ret[i] = PRNG();
    }

    return ret;
}

static std::string getBignum(bool mustBePositive = false) {
    std::string ret;

    if ( (PRNG() % 10) == 0 ) {
        constexpr long sizeMax = cryptofuzz::config::kMaxBignumSize;
        constexpr long sizeTop = sizeMax * 0.5;
        constexpr long sizeBottom = sizeMax - sizeTop;

        static_assert(sizeBottom > 0);
        static_assert(sizeBottom + sizeTop <= sizeMax);

        const size_t size = (PRNG() % sizeTop) + sizeBottom;

        for (size_t i = 0; i < size; i++) {
            char c = '0' + (PRNG() % 10);
            if ( i == 0 && c == '0' ) {
                /* Cannot have leading zeroes */
                c = '1';
            }
            ret += c;
        }
    } else {
        if ( getBool() ) {
            ret = Pool_Bignum.Get();
        } else {
            ret = cryptofuzz::numbers.at(PRNG() % cryptofuzz::numbers.size());
        }
    }

    const bool isNegative = !ret.empty() && ret[0] == '-';
    if ( cryptofuzz::config::kNegativeIntegers == false ) {
        mustBePositive = true;
    }

    if ( isNegative && mustBePositive ) {
        ret = std::string(ret.data() + 1, ret.size() - 1);
    }

    if ( !mustBePositive && !isNegative && getBool() ) {
        ret = "-" + ret;
    }

    return ret;
}

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t maxSize);

extern cryptofuzz::Options* cryptofuzz_options;

static uint64_t getRandomCipher(void) {
    if ( !cryptofuzz_options->ciphers.Empty() ) {
        return cryptofuzz_options->ciphers.At(PRNG());
    } else {
        return CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
    }
}

static uint64_t getRandomDigest(void) {
    if ( !cryptofuzz_options->digests.Empty() ) {
        return cryptofuzz_options->digests.At(PRNG());
    } else {
        return DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;
    }
}

static uint64_t getRandomCurve(void) {
    if ( !cryptofuzz_options->curves.Empty() ) {
        return cryptofuzz_options->curves.At(PRNG());
    } else {
        return ECC_CurveLUT[ PRNG() % (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])) ].id;
    }
}

static uint64_t getRandomCalcOp(void) {
    if ( !cryptofuzz_options->calcOps.Empty() ) {
        return cryptofuzz_options->calcOps.At(PRNG());
    } else {
        return CalcOpLUT[ PRNG() % (sizeof(CalcOpLUT) / sizeof(CalcOpLUT[0])) ].id;
    }
}

static std::string get_BLS_PyECC_DST(void) {
    return "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f";
}

static std::string get_BLS_BasicScheme_DST(void) {
    return "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f4e554c5f";
}

static std::string get_BLS_predefined_DST(void) {
    return getBool() ? get_BLS_PyECC_DST() : get_BLS_BasicScheme_DST();
}

static void generateECCPoint(void) {
    if ( (PRNG() % 100) != 0 ) {
        return;
    }

    const auto curveID = getRandomCurve();

    const auto a = cryptofuzz::repository::ECC_CurveToA(curveID);
    if ( a == std::nullopt ) {
        return;
    }

    const auto b = cryptofuzz::repository::ECC_CurveToB(curveID);
    if ( b == std::nullopt ) {
        return;
    }

    const auto p = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( p == std::nullopt ) {
        return;
    }

    const auto o = cryptofuzz::repository::ECC_CurveToPrime(curveID);
    if ( o == std::nullopt ) {
        return;
    }

    const auto x = getBignum(true);

    const auto y = cryptofuzz::util::Find_ECC_Y(x, *a, *b, *p, *o, getBool());

    Pool_CurveECC_Point.Set({ curveID, x, y });
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t maxSize, unsigned int seed) {
    (void)seed;
    std::vector<uint8_t> modifier;
    bool reuseModifier;

    if ( maxSize < 64 || getBool() ) {
        goto end;
    }

    reuseModifier = getBool();

    if ( reuseModifier == true ) {
        cryptofuzz::util::MemorySanitizerUnpoison(data, size);

        /* Try to extract modifier from input */
        try {
            fuzzing::datasource::Datasource ds(data, size);
            /* ignore result */ ds.Get<uint64_t>();
            /* ignore result */ ds.GetData(0, 1);
            modifier = ds.GetData(0);
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
    }

    {
        uint64_t operation;

        if ( !cryptofuzz_options->operations.Empty() ) {
            operation = cryptofuzz_options->operations.At(PRNG());
        } else {
            operation = OperationLUT[ PRNG() % (sizeof(OperationLUT) / sizeof(OperationLUT[0])) ].id;
        }

        fuzzing::datasource::Datasource dsOut2(nullptr, 0);

        nlohmann::json parameters;

#define GET_OR_BIGNUM(x) getBool() ? (x) : getBignum();
        switch ( operation ) {
            case    CF_OPERATION("Digest"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Digest op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("HMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);
                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::HMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("CMAC"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["cleartext"] = getBuffer(lengths[1]);
                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);
                    parameters["cipher"]["cipherType"] = getRandomCipher();

                    cryptofuzz::operation::CMAC op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricEncrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tagSize_enabled = PRNG() % 2;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["cleartext"] = getBuffer(lengths[1]);

                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tagSize_enabled ) {
                        parameters["tagSize_enabled"] = true;
                        if ( getBool() ) {
                            parameters["tagSize"] = getDefaultSize();
                        } else {
                            parameters["tagSize"] = PRNG() % 102400;
                        }
                    } else {
                        parameters["tagSize_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["ciphertextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricEncrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SymmetricDecrypt"):
                {
                    const bool aad_enabled = PRNG() % 2;
                    const bool tag_enabled = PRNG() % 2;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    if ( aad_enabled ) {
                        numParts++; /* aad */
                    }
                    if ( tag_enabled ) {
                        numParts++; /* tag */
                    }

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    if ( getBool() ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["ciphertext"] = getBuffer(lengths[1]);

                    parameters["cipher"]["iv"] = getBuffer(lengths[2], true);
                    parameters["cipher"]["key"] = getBuffer(lengths[3], true);

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( getBool() ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = getBuffer(lengths[4]);
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tag_enabled ) {
                        parameters["tag_enabled"] = true;
                        parameters["tag"] = getBuffer(lengths[aad_enabled ? 5 : 4], true);
                    } else {
                        parameters["tag_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = getRandomCipher();
                    parameters["cleartextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricDecrypt op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BignumCalc"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_R"):
            case    CF_OPERATION("BignumCalc_Mod_BLS12_381_P"):
            case    CF_OPERATION("BignumCalc_Mod_2Exp256"):
            case    CF_OPERATION("BignumCalc_Mod_SECP256K1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = getRandomCalcOp();
                    parameters["bn1"] = getBignum();
                    parameters["bn2"] = getBignum();
                    parameters["bn3"] = getBignum();
                    parameters["bn4"] = "";

                    cryptofuzz::operation::BignumCalc op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = getRandomCalcOp();
                    parameters["bn1"] = getBignum();
                    parameters["bn2"] = getBignum();
                    parameters["bn3"] = getBignum();
                    parameters["bn4"] = "";

                    cryptofuzz::operation::BignumCalc op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                        const auto P1 = Pool_CurvePrivkey.Get();

                        parameters["curveType"] = P1.curveID;
                        parameters["priv"] = P1.priv;
                    } else {
                        const auto curveID = getRandomCurve();
                        parameters["curveType"] = curveID;

                        if ( getBool() ) {
                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                parameters["priv"] = boost::lexical_cast<std::string>(o-1);
                            } else {
                                parameters["priv"] = getBignum();
                            }
                        } else {
                            parameters["priv"] = getBignum();
                        }

                    }

                    cryptofuzz::operation::ECC_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_ValidatePubkey"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurveKeypair.Have() ) {
                        const auto P = Pool_CurveKeypair.Get();

                        parameters["curveType"] = P.curveID;

                        parameters["pub_x"] = getBool() ? getBignum() : P.pub_x;
                        parameters["pub_y"] = getBool() ? getBignum() : P.pub_y;
                    } else {
                        parameters["curveType"] = getRandomCurve();
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_ValidatePubkey op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                        const auto P1 = Pool_CurveKeypair.Get();
                        const auto P2 = Pool_CurveKeypair.Get();

                        CF_CHECK_EQ(P1.curveID, P2.curveID);

                        parameters["curveType"] = P1.curveID;

                        parameters["priv"] = P1.privkey;

                        parameters["pub_x"] = P1.pub_x;
                        parameters["pub_y"] = P1.pub_y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["priv"] = getBignum();

                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECDH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECGDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECRDSA_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    const auto P1 = Pool_CurvePrivkey.Get();

                    parameters["curveType"] = P1.curveID;
                    parameters["priv"] = P1.priv;
                    parameters["nonce"] = getBignum();

                    if ( getBool() ) {
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    } else {
                        parameters["cleartext"] = getBuffer(PRNG() % 32);
                    }
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Schnorr_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECGDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECGDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECGDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECRDSA_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test ECRDSA signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECRDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("Schnorr_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"]["pub"][0] = getBool() ? getBignum() : P.pub_x;
                        parameters["signature"]["pub"][1] = getBool() ? getBignum() : P.pub_y;

                        parameters["signature"]["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        auto sigS = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            /* Test Schnorr signature malleability */

                            const auto order = cryptofuzz::repository::ECC_CurveToOrder(P.curveID);
                            if ( order != std::nullopt ) {
                                const auto o = boost::multiprecision::cpp_int(*order);
                                const auto s = boost::multiprecision::cpp_int(sigS);
                                if ( o > s ) {
                                    sigS = boost::lexical_cast<std::string>(o - s);
                                }
                            }
                        }

                        parameters["signature"]["signature"][1] = sigS;
                        parameters["cleartext"] = P.cleartext;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::Schnorr_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECDSA_Recover"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    if ( getBool() && Pool_CurveECDSASignature.Have() == true ) {
                        const auto P = Pool_CurveECDSASignature.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["signature"][0] = getBool() ? getBignum() : P.sig_r;
                        parameters["signature"][1] = getBool() ? getBignum() : P.sig_y;

                        if ( getBool() ) {
                            parameters["cleartext"] = P.cleartext;
                        } else {
                            parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                        }
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"][0] = getBignum();
                        parameters["signature"][1] = getBignum();

                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                    }

                    parameters["id"] = PRNG() % 4;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Recover op(parameters);
                    op.Serialize(dsOut2);
                }
            case    CF_OPERATION("ECC_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["curveType"] = getRandomCurve();

                    cryptofuzz::operation::ECC_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECIES_Encrypt"):
            case    CF_OPERATION("ECIES_Decrypt"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    } else {
                        parameters["ciphertext"] = getBuffer(PRNG() % 1024);
                    }
                    //parameters["cipherType"] = getRandomCipher();
                    parameters["cipherType"] = CF_CIPHER("AES_128_CBC");
                    parameters["iv_enabled"] = false;

                    parameters["priv"] = getBignum();

                    if ( Pool_CurveKeypair.Have() && getBool() == true ) {
                        const auto P = Pool_CurveKeypair.Get();

                        parameters["curveType"] = P.curveID;
                        parameters["pub_x"] = P.pub_x;
                        parameters["pub_y"] = P.pub_y;

                        if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                            const auto P2 = Pool_CurvePrivkey.Get();
                            if ( P2.curveID == P.curveID ) {
                                parameters["priv"] = P2.priv;
                            }
                        }
                    } else {
                        parameters["curveType"] = getRandomCurve();
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                    }

                    if ( operation == CF_OPERATION("ECIES_Encrypt") ) {
                        cryptofuzz::operation::ECIES_Encrypt op(parameters);
                        op.Serialize(dsOut2);
                    } else {
                        cryptofuzz::operation::ECIES_Decrypt op(parameters);
                        op.Serialize(dsOut2);
                    }
                }
                break;
            case    CF_OPERATION("ECC_Point_Add"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["b_x"] = getBool() ? getBignum() : P.x;
                        parameters["b_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::ECC_Point_Add op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("ECC_Point_Mul"):
                {
                    parameters["modifier"] = "";

                    if ( Pool_CurveECC_Point.Have() == true ) {
                        const auto P = Pool_CurveECC_Point.Get();
                        parameters["curveType"] = P.curveID;

                        parameters["a_x"] = getBool() ? getBignum() : P.x;
                        parameters["a_y"] = getBool() ? getBignum() : P.y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::ECC_Point_Mul op(parameters);
                    op.Serialize(dsOut2);

                    generateECCPoint();
                }
                break;
            case    CF_OPERATION("KDF_SCRYPT"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["N"] = PRNG() % 5;
                    parameters["r"] = PRNG() % 9;
                    parameters["p"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_SCRYPT op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_HKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["info"] = getBuffer(lengths[3]);
                    parameters["keySize"] = PRNG() % 17000;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_HKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_TLS1_PRF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* seed */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["seed"] = getBuffer(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_TLS1_PRF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF1"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_PBKDF2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_PBKDF2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_ARGON2"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["password"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["type"] = PRNG() % 3;
                    parameters["threads"] = PRNG() % 256;
                    parameters["memory"] = PRNG() % (64*1024);
                    parameters["iterations"] = PRNG() % 3;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_ARGON2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SSH"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* key */
                    numParts++; /* xcghash */
                    numParts++; /* session_id */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["key"] = getBuffer(lengths[1]);
                    parameters["xcghash"] = getBuffer(lengths[2]);
                    parameters["session_id"] = getBuffer(lengths[3]);
                    parameters["type"] = getBuffer(1);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_SSH op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_X963"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* info */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["info"] = getBuffer(lengths[2]);
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::KDF_X963 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("KDF_SP_800_108"):
                {
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* secret */
                    numParts++; /* salt */
                    numParts++; /* label */

                    const auto lengths = SplitLength(maxSize - 64, numParts);

                    if ( getBool() == true ) {
                        /* MAC = HMAC */
                        parameters["mech"]["mode"] = true;
                        parameters["mech"]["type"] = getRandomDigest();
                    } else {
                        /* MAC = CMAC */
                        parameters["mech"]["mode"] = false;
                        parameters["mech"]["type"] = getRandomCipher();
                    }

                    parameters["modifier"] = getBuffer(lengths[0]);
                    parameters["secret"] = getBuffer(lengths[1]);
                    parameters["salt"] = getBuffer(lengths[2]);
                    parameters["label"] = getBuffer(lengths[3]);
                    parameters["mode"] = PRNG() % 3;
                    parameters["keySize"] = PRNG() % 17000;

                    cryptofuzz::operation::KDF_SP_800_108 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getBignum();
                    parameters["base"] = getBignum();

                    cryptofuzz::operation::DH_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("DH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["prime"] = getBignum();
                    parameters["base"] = getBignum();
                    if ( Pool_DH_PublicKey.Have() && getBool() == true ) {
                        parameters["pub"] = Pool_DH_PublicKey.Get();
                    } else {
                        parameters["pub"] = getBignum();
                    }

                    if ( Pool_DH_PrivateKey.Have() && getBool() == true ) {
                        parameters["priv"] = Pool_DH_PrivateKey.Get();
                    } else {
                        parameters["priv"] = getBignum();
                    }

                    cryptofuzz::operation::DH_Derive op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_PrivateToPublic_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_PrivateToPublic_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Sign"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    const auto hashOrPoint = getBool();
                    //const auto hashOrPoint = false;
                    parameters["hashOrPoint"] = hashOrPoint;
                    if ( hashOrPoint == true ) {
                        //parameters["cleartext"] = getBuffer(PRNG() % 32);
                        parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);
                        parameters["point_v"] = "";
                        parameters["point_w"] = "";
                        parameters["point_x"] = "";
                        parameters["point_y"] = "";
                    } else {
                        if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                            const auto P = Pool_CurveBLSG2.Get();
                            parameters["point_v"] = GET_OR_BIGNUM(P.g2_v);
                            parameters["point_w"] = GET_OR_BIGNUM(P.g2_w);
                            parameters["point_x"] = GET_OR_BIGNUM(P.g2_x);
                            parameters["point_y"] = GET_OR_BIGNUM(P.g2_y);
                        } else {
                            parameters["point_v"] = getBignum();
                            parameters["point_w"] = getBignum();
                            parameters["point_x"] = getBignum();
                            parameters["point_y"] = getBignum();
                        }

                        parameters["cleartext"] = "";
                    }
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["aug"] = "";
                    parameters["priv"] = getBignum();

                    cryptofuzz::operation::BLS_Sign op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurveBLSSignature.Have() == true ) {
                        const auto P = Pool_CurveBLSSignature.Get();

                        parameters["curveType"] = P.curveID;
                        parameters["hashOrPoint"] = P.hashOrPoint;
                        parameters["point_v"] = GET_OR_BIGNUM(P.point_v);
                        parameters["point_w"] = GET_OR_BIGNUM(P.point_w);
                        parameters["point_x"] = GET_OR_BIGNUM(P.point_x);
                        parameters["point_y"] = GET_OR_BIGNUM(P.point_y);
                        parameters["cleartext"] = P.cleartext;
                        parameters["dest"] = P.dest;
                        parameters["aug"] = P.aug;
                        parameters["pub_x"] = GET_OR_BIGNUM(P.pub_x);
                        parameters["pub_y"] = GET_OR_BIGNUM(P.pub_y);
                        parameters["sig_v"] = GET_OR_BIGNUM(P.sig_v);
                        parameters["sig_w"] = GET_OR_BIGNUM(P.sig_w);
                        parameters["sig_x"] = GET_OR_BIGNUM(P.sig_x);
                        parameters["sig_y"] = GET_OR_BIGNUM(P.sig_y);
                    } else {
                        parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                        const auto hashOrPoint = getBool();
                        parameters["hashOrPoint"] = hashOrPoint;
                        if ( hashOrPoint == true ) {
                            parameters["cleartext"] = getBuffer(PRNG() % 32);
                            parameters["point_v"] = "";
                            parameters["point_w"] = "";
                            parameters["point_x"] = "";
                            parameters["point_y"] = "";
                        } else {
                            parameters["point_v"] = getBignum();
                            parameters["point_w"] = getBignum();
                            parameters["point_x"] = getBignum();
                            parameters["point_y"] = getBignum();
                            parameters["cleartext"] = "";
                        }
                        parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                        parameters["pub_x"] = getBignum();
                        parameters["pub_y"] = getBignum();
                        parameters["sig_v"] = getBignum();
                        parameters["sig_w"] = getBignum();
                        parameters["sig_x"] = getBignum();
                        parameters["sig_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_IsG1OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_IsG1OnCurve op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_IsG2OnCurve"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_IsG2OnCurve op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["ikm"] = getBuffer(PRNG() % 512);
                    parameters["info"] = getBuffer(PRNG() % 512);

                    cryptofuzz::operation::BLS_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["compressed"] = getBignum();

                    cryptofuzz::operation::BLS_Decompress_G1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["g1_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["g1_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["g1_x"] = getBignum();
                        parameters["g1_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Compress_G1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Decompress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["g1_x"] = getBignum();
                    parameters["g1_y"] = getBignum();

                    cryptofuzz::operation::BLS_Decompress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Compress_G2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["g2_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["g2_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["g2_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["g2_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["g2_v"] = getBignum();
                        parameters["g2_w"] = getBignum();
                        parameters["g2_x"] = getBignum();
                        parameters["g2_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_Compress_G2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG1"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();

                    parameters["aug"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG1 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_HashToG2"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();
                    parameters["aug"] = getBuffer(PRNG() % 1024);

                    cryptofuzz::operation::BLS_HashToG2 op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_Pairing"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    parameters["dest"] = getBool() ? getBuffer(PRNG() % 512) : get_BLS_predefined_DST();

                    nlohmann::json components = nlohmann::json::array();

                    const auto numComponents = PRNG() % 16;

                    for (size_t i = 0; i < numComponents; i++) {
                        nlohmann::json component;

                        if ( Pool_CurveBLSSignature.Have() == true ) {
                            const auto P = Pool_CurveBLSSignature.Get();

                            component["msg"] = P.cleartext;
                            parameters["dest"] = P.dest;
                            component["aug"] = P.aug;
                            component["pub_x"] = GET_OR_BIGNUM(P.pub_x);
                            component["pub_y"] = GET_OR_BIGNUM(P.pub_y);
                            component["sig_v"] = GET_OR_BIGNUM(P.sig_v);
                            component["sig_w"] = GET_OR_BIGNUM(P.sig_w);
                            component["sig_x"] = GET_OR_BIGNUM(P.sig_x);
                            component["sig_y"] = GET_OR_BIGNUM(P.sig_y);
                        } else {
                            if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                                const auto P = Pool_CurveBLSG2.Get();
                                component["sig_v"] = GET_OR_BIGNUM(P.g2_v);
                                component["sig_w"] = GET_OR_BIGNUM(P.g2_w);
                                component["sig_x"] = GET_OR_BIGNUM(P.g2_x);
                                component["sig_y"] = GET_OR_BIGNUM(P.g2_y);
                            } else {
                                component["sig_v"] = getBignum();
                                component["sig_w"] = getBignum();
                                component["sig_x"] = getBignum();
                                component["sig_y"] = getBignum();
                            }

                            if ( Pool_CurveKeypair.Have() ) {
                                const auto P = Pool_CurveKeypair.Get();
                                component["pub_x"] = GET_OR_BIGNUM(P.pub_x);
                                component["pub_y"] = GET_OR_BIGNUM(P.pub_y);
                            } else {
                                component["pub_x"] = getBignum();
                                component["pub_y"] = getBignum();
                            }

                            component["msg"] = getBuffer(PRNG() % 1024);
                            component["aug"] = getBuffer(PRNG() % 1024);
                        }

                        components.push_back(component);
                    }

                    parameters["components"] = components;

                    cryptofuzz::operation::BLS_Pairing op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["b_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_Add op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::BLS_G1_Mul op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["b_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_IsEq op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G1_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG1.Have() == true ) {
                        const auto P = Pool_CurveBLSG1.Get();
                        parameters["a_x"] = GET_OR_BIGNUM(P.g1_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g1_y);
                    } else {
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G1_Neg op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Add"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["b_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["b_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["b_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["b_v"] = getBignum();
                        parameters["b_w"] = getBignum();
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_Add op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Mul"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    parameters["b"] = getBignum();

                    cryptofuzz::operation::BLS_G2_Mul op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_IsEq"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["b_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["b_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["b_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["b_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["b_v"] = getBignum();
                        parameters["b_w"] = getBignum();
                        parameters["b_x"] = getBignum();
                        parameters["b_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_IsEq op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("BLS_G2_Neg"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["curveType"] = CF_ECC_CURVE("BLS12_381");

                    if ( getBool() && Pool_CurveBLSG2.Have() == true ) {
                        const auto P = Pool_CurveBLSG2.Get();
                        parameters["a_v"] = GET_OR_BIGNUM(P.g2_v);
                        parameters["a_w"] = GET_OR_BIGNUM(P.g2_w);
                        parameters["a_x"] = GET_OR_BIGNUM(P.g2_x);
                        parameters["a_y"] = GET_OR_BIGNUM(P.g2_y);
                    } else {
                        parameters["a_v"] = getBignum();
                        parameters["a_w"] = getBignum();
                        parameters["a_x"] = getBignum();
                        parameters["a_y"] = getBignum();
                    }

                    cryptofuzz::operation::BLS_G2_Neg op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("SR25519_Verify"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1024);

                    parameters["signature"]["pub"] = getBignum();

                    parameters["signature"]["signature"][0] = getBignum();
                    parameters["signature"]["signature"][1] = getBignum();

                    parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), (PRNG() % 64) * 2);

                    cryptofuzz::operation::SR25519_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            default:
                goto end;
        }
#undef GET_OR_BIGNUM

        fuzzing::datasource::Datasource dsOut(nullptr, 0);

        /* Operation ID */
        dsOut.Put<uint64_t>(operation);

        dsOut.PutData(dsOut2.GetOut());

        /* Modifier */
        if ( reuseModifier == true && !modifier.empty() ) {
            dsOut.PutData(modifier);
        } else {
            size_t modifierMaxSize = maxSize / 10;
            if ( modifierMaxSize == 0 ) {
                modifierMaxSize = 1;
            }

            dsOut.PutData(getBufferBin(PRNG() % modifierMaxSize));
        }

        /* Module ID */
        dsOut.Put<uint64_t>( ModuleLUT[ PRNG() % (sizeof(ModuleLUT) / sizeof(ModuleLUT[0])) ].id );

        /* Terminator */
        dsOut.Put<bool>(false);

        const auto insertSize = dsOut.GetOut().size();
        if ( insertSize <= maxSize ) {
            memcpy(data, dsOut.GetOut().data(), insertSize);

            /* Fall through to LLVMFuzzerMutate */
        }
    }

end:
    return LLVMFuzzerMutate(data, size, maxSize);
}
