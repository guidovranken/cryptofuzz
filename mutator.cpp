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

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t maxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t maxSize, unsigned int seed) {
    (void)seed;
    if ( PRNG() % 2 == 0 ) {
        goto end;
    }

    {
        const uint64_t operation = OperationLUT[ PRNG() % (sizeof(OperationLUT) / sizeof(OperationLUT[0])) ].id;

        fuzzing::datasource::Datasource dsOut(nullptr, 0);

        /* Operation ID */
        dsOut.Put<uint64_t>(operation);

        std::vector<uint8_t> toAdd;

        switch ( operation ) {
            case    CF_OPERATION("SymmetricEncrypt"):
                {
                    nlohmann::json parameters;
                    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                    parameters["modifier"] = std::string((PRNG() % 1000) * 2, '0');
                    parameters["cleartext"] = std::string((PRNG() % maxSize) * 2, '0');
                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> ivSizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto ivSize = ivSizes[PRNG() % ivSizes.size()];
                        parameters["cipher"]["iv"] = std::string(ivSize * 2, '0');
                    } else {
                        parameters["cipher"]["iv"] = std::string((PRNG() % maxSize) * 2, '0');
                    }
                    if ( PRNG() % 2 == 0 ) {
                        static const std::vector<size_t> keySizes = {0, 1, 2, 4, 8, 12, 16, 24, 32, 64};
                        const auto keySize = keySizes[PRNG() % keySizes.size()];
                        parameters["cipher"]["key"] = std::string(keySize * 2, '0');
                    } else {
                        parameters["cipher"]["key"] = std::string((PRNG() % maxSize) * 2, '0');
                    }
                    parameters["cipher"]["cipherType"] = CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
                    if ( PRNG() % 2 == 0 ) {
                        parameters["aad_enabled"] = true;
                        parameters["aad"] = std::string((PRNG() % maxSize) * 2, '0');
                    } else {
                        parameters["aad_enabled"] = false;
                    }

                    parameters["ciphertextSize"] = PRNG();

                    if ( PRNG() % 2 == 0 ) {
                        parameters["tagSize_enabled"] = true;
                        parameters["tagSize"] = PRNG();
                    } else {
                        parameters["tagSize_enabled"] = false;
                    }

                    cryptofuzz::operation::SymmetricEncrypt op(parameters);
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
            default:
                goto end;
        }
        dsOut.PutData(toAdd);

        /* Modifier */
        dsOut.PutData(std::vector<uint8_t>(PRNG() % 256));

        /* Module ID */
        dsOut.Put<uint64_t>( ModuleLUT[ PRNG() % (sizeof(ModuleLUT) / sizeof(ModuleLUT[0])) ].id );

        /* Terminator */
        dsOut.Put<bool>(false);

        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        dsOut.PutData(std::vector<uint8_t>(PRNG() % maxSize));

        const auto insertSize = dsOut.GetOut().size();
        if ( insertSize <= maxSize ) {
            memcpy(data, dsOut.GetOut().data(), insertSize);
        }
    }

end:
    return LLVMFuzzerMutate(data, size, maxSize);
}
