#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/repository.h>
#include "repository_tbl.h"
#include "numbers.h"
#include "third_party/json/json.hpp"

static uint32_t PRNG()
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

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t maxSize);

static std::string getBuffer(size_t size) {
    if ( PRNG() % 2 == 0 ) {
        static const std::vector<size_t> defaultSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
        const auto newSize = defaultSizes[PRNG() % defaultSizes.size()];
        if ( newSize < size ) {
            size = newSize;
        }
    }

    return std::string(size * 2, '0');
}
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t maxSize, unsigned int seed) {
    (void)seed;
    if ( maxSize < 64 || PRNG() % 2 == 0 ) {
        goto end;
    }
    {
        const uint64_t operation = OperationLUT[ PRNG() % (sizeof(OperationLUT) / sizeof(OperationLUT[0])) ].id;

        fuzzing::datasource::Datasource dsOut(nullptr, 0);

        /* Operation ID */
        dsOut.Put<uint64_t>(operation);

        std::vector<uint8_t> toAdd;

        switch ( operation ) {
            case    CF_OPERATION("Digest"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["cleartext"] = std::string(lengths[1] * 2, '0');
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::Digest op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("HMAC"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["cleartext"] = std::string(lengths[1] * 2, '0');
                    parameters["cipher"]["iv"] = getBuffer(lengths[2]);
                    parameters["cipher"]["key"] = getBuffer(lengths[3]);
                    parameters["cipher"]["cipherType"] = CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::HMAC op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("CMAC"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* cleartext */
                    numParts++; /* iv */
                    numParts++; /* key */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["cleartext"] = std::string(lengths[1] * 2, '0');
                    parameters["cipher"]["iv"] = getBuffer(lengths[2]);
                    parameters["cipher"]["key"] = getBuffer(lengths[3]);
                    parameters["cipher"]["cipherType"] = CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;

                    cryptofuzz::operation::CMAC op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("SymmetricEncrypt"):
                {
                    nlohmann::json parameters;
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

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    if ( PRNG() % 2 == 0 ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["cleartext"] = std::string(lengths[1] * 2, '0');

                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> ivSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto newIvSize = ivSizes[PRNG() % ivSizes.size()];
                        if ( newIvSize < lengths[2] ) {
                            lengths[2] = newIvSize;
                        }
                    }
                    parameters["cipher"]["iv"] = std::string(lengths[2] * 2, '0');

                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> keySizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto newKeySize = keySizes[PRNG() % keySizes.size()];
                        if ( newKeySize < lengths[3] ) {
                            lengths[3] = newKeySize;
                        }
                    }
                    parameters["cipher"]["key"] = std::string(lengths[3] * 2, '0');

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( PRNG() % 2 == 0 ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = std::string(lengths[4] * 2, '0');
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tagSize_enabled ) {
                        parameters["tagSize_enabled"] = true;
                        if ( PRNG() % 2 == 0 ) {
                            static const std::vector<size_t> tagSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                            const auto newTagSize = tagSizes[PRNG() % tagSizes.size()];
                            parameters["tagSize"] = newTagSize;
                        } else {
                            parameters["tagSize"] = PRNG() % 102400;
                        }
                    } else {
                        parameters["tagSize_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
                    parameters["ciphertextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricEncrypt op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("SymmetricDecrypt"):
                {
                    nlohmann::json parameters;
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

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    if ( PRNG() % 2 == 0 ) {
                        if ( 16 < lengths[1] ) {
                            lengths[1] = 16;
                        }
                    }
                    parameters["ciphertext"] = std::string(lengths[1] * 2, '0');

                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> ivSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto newIvSize = ivSizes[PRNG() % ivSizes.size()];
                        if ( newIvSize < lengths[2] ) {
                            lengths[2] = newIvSize;
                        }
                    }
                    parameters["cipher"]["iv"] = std::string(lengths[2] * 2, '0');

                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> keySizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto newKeySize = keySizes[PRNG() % keySizes.size()];
                        if ( newKeySize < lengths[3] ) {
                            lengths[3] = newKeySize;
                        }
                    }
                    parameters["cipher"]["key"] = std::string(lengths[3] * 2, '0');

                    if ( aad_enabled ) {
                        parameters["aad_enabled"] = true;
                        if ( PRNG() % 2 == 0 ) {
                            lengths[4] = 0;
                        }
                        parameters["aad"] = std::string(lengths[4] * 2, '0');
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    if ( tag_enabled ) {
                        parameters["tag_enabled"] = true;
                        parameters["tag"] = getBuffer(lengths[aad_enabled ? 5 : 4]);
                    } else {
                        parameters["tag_enabled"] = false;
                    }

                    parameters["cipher"]["cipherType"] = CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
                    parameters["cleartextSize"] = PRNG() % (lengths[1] + 9);

                    cryptofuzz::operation::SymmetricDecrypt op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("BignumCalc"):
                {
                    nlohmann::json parameters;
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    parameters["modifier"] = std::string((PRNG() % 1000) * 2, '0');
                    parameters["calcOp"] = CalcOpLUT[ PRNG() % (sizeof(CalcOpLUT) / sizeof(CalcOpLUT[0])) ].id;
                    parameters["bn1"] = numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];
                    parameters["bn2"] = numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];
                    parameters["bn3"] = numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];
                    parameters["bn4"] = numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];

                    cryptofuzz::operation::BignumCalc op(parameters);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("ECC_PrivateToPublic"):
                {
                    nlohmann::json parameters;
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);

                    parameters["modifier"] = std::string((PRNG() % 1000) * 2, '0');
                    parameters["curveType"] = ECC_CurveLUT[ PRNG() % (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])) ].id;
                    parameters["priv"] = numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];

                    cryptofuzz::operation::ECC_PrivateToPublic op(parameters);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_SCRYPT"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["N"] = PRNG() % 5;
                    parameters["r"] = PRNG() % 9;
                    parameters["p"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_SCRYPT op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_HKDF"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */
                    numParts++; /* info */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["info"] = std::string(lengths[3] * 2, '0');
                    parameters["keySize"] = PRNG() % 17000;
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::KDF_HKDF op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_PBKDF"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_PBKDF1"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::KDF_PBKDF op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_PBKDF2"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["iterations"] = PRNG() % 5;
                    parameters["keySize"] = PRNG() % 1024;
                    parameters["digestType"] = DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;

                    cryptofuzz::operation::KDF_PBKDF2 op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            case    CF_OPERATION("KDF_ARGON2"):
                {
                    nlohmann::json parameters;
                    size_t numParts = 0;

                    numParts++; /* modifier */
                    numParts++; /* password */
                    numParts++; /* salt */

                    auto lengths = SplitLength(maxSize - 64, numParts);

                    parameters["modifier"] = std::string(lengths[0] * 2, '0');
                    parameters["password"] = std::string(lengths[1] * 2, '0');
                    parameters["salt"] = std::string(lengths[2] * 2, '0');
                    parameters["type"] = PRNG() % 3;
                    parameters["threads"] = PRNG() % 256;
                    parameters["memory"] = PRNG() % (64*1024);
                    parameters["iterations"] = PRNG() % 3;
                    parameters["keySize"] = PRNG() % 1024;

                    cryptofuzz::operation::KDF_ARGON2 op(parameters);
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    op.Serialize(dsOut2);
                    const auto opSerialized = dsOut2.GetOut();
                    std::copy(opSerialized.begin(), opSerialized.end(), std::back_inserter(toAdd));
                }
                break;
            default:
                goto end;
        }
        dsOut.PutData(toAdd);

        /* Modifier */
        dsOut.PutData(std::vector<uint8_t>(0));

        /* Module ID */
        dsOut.Put<uint64_t>( ModuleLUT[ PRNG() % (sizeof(ModuleLUT) / sizeof(ModuleLUT[0])) ].id );

        /* Terminator */
        dsOut.Put<bool>(false);

        const auto insertSize = dsOut.GetOut().size();
        if ( insertSize <= maxSize ) {
            memcpy(data, dsOut.GetOut().data(), insertSize);
        }
    }

end:
    return LLVMFuzzerMutate(data, size, maxSize);
}
