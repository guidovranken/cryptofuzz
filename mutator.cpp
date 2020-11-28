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
    if ( alternativeSize == true ) {
        if ( getBool() ) {
            const auto newSize = getDefaultSize();
            if ( newSize < size ) {
                size = newSize;
            }
        }
    }

    return std::string(size * 2, '0');
}

static std::string getBignum(const bool positive = false) {
    if ( Pool_Bignum.Have() && getBool() ) {
        const auto ret = Pool_Bignum.Get();
        if ( positive && !ret.empty() && ret[0] == '-' ) {
            goto end;
        }
        return ret;
    }
end:
    return numbers[PRNG() % (sizeof(numbers) / sizeof(numbers[0]))];
}

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t maxSize);

extern cryptofuzz::Options* cryptofuzz_options;

uint64_t getRandomCipher(void) {
    if ( cryptofuzz_options && cryptofuzz_options->ciphers != std::nullopt ) {
        return (*cryptofuzz_options->ciphers)[PRNG() % cryptofuzz_options->ciphers->size()];
    } else {
        return CipherLUT[ PRNG() % (sizeof(CipherLUT) / sizeof(CipherLUT[0])) ].id;
    }
}

uint64_t getRandomDigest(void) {
    if ( cryptofuzz_options && cryptofuzz_options->digests != std::nullopt ) {
        return (*cryptofuzz_options->digests)[PRNG() % cryptofuzz_options->digests->size()];
    } else {
        return DigestLUT[ PRNG() % (sizeof(DigestLUT) / sizeof(DigestLUT[0])) ].id;
    }
}

uint64_t getRandomCurve(void) {
    if ( cryptofuzz_options && cryptofuzz_options->curves != std::nullopt ) {
        return (*cryptofuzz_options->curves)[PRNG() % cryptofuzz_options->curves->size()];
    } else {
        return ECC_CurveLUT[ PRNG() % (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])) ].id;
    }
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t maxSize, unsigned int seed) {
    (void)seed;

    if ( maxSize < 64 || getBool() ) {
        goto end;
    }

    {
        uint64_t operation;

        if ( cryptofuzz_options && cryptofuzz_options->operations != std::nullopt ) {
            operation = (*cryptofuzz_options->operations)[PRNG() % cryptofuzz_options->operations->size()];
        } else {
            operation = OperationLUT[ PRNG() % (sizeof(OperationLUT) / sizeof(OperationLUT[0])) ].id;
        }

        fuzzing::datasource::Datasource dsOut2(nullptr, 0);

        nlohmann::json parameters;

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
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);
                    parameters["calcOp"] = CalcOpLUT[ PRNG() % (sizeof(CalcOpLUT) / sizeof(CalcOpLUT[0])) ].id;
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
            case    CF_OPERATION("ECDH_Derive"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 1000);

                    if ( Pool_CurvePrivkey.Have() && getBool() == true ) {
                        const auto P1 = Pool_CurveKeypair.Get();
                        const auto P2 = Pool_CurveKeypair.Get();

                        CF_CHECK_EQ(P1.curveID, P2.curveID);

                        parameters["curveType"] = P1.curveID;

                        parameters["pub1_x"] = P1.pub_x;
                        parameters["pub1_y"] = P1.pub_y;

                        parameters["pub2_x"] = P2.pub_x;
                        parameters["pub2_y"] = P2.pub_y;
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["pub1_x"] = getBignum();
                        parameters["pub1_y"] = getBignum();

                        parameters["pub2_x"] = getBignum();
                        parameters["pub2_y"] = getBignum();
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

                    parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), 64);
                    parameters["nonceSource"] = PRNG() % 3;
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Sign op(parameters);
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
                    } else {
                        parameters["curveType"] = getRandomCurve();

                        parameters["signature"]["pub"][0] = getBignum();
                        parameters["signature"]["pub"][1] = getBignum();

                        parameters["signature"]["signature"][0] = getBignum();
                        parameters["signature"]["signature"][1] = getBignum();
                    }

                    parameters["cleartext"] = cryptofuzz::util::DecToHex(getBignum(true), 64);
                    parameters["digestType"] = getRandomDigest();

                    cryptofuzz::operation::ECDSA_Verify op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECC_GenerateKeyPair"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["curveType"] = getRandomCurve();

                    cryptofuzz::operation::ECC_GenerateKeyPair op(parameters);
                    op.Serialize(dsOut2);
                }
                break;
            case    CF_OPERATION("ECIES_Encrypt"):
                {
                    parameters["modifier"] = getBuffer(PRNG() % 128);
                    parameters["cleartext"] = getBuffer(PRNG() % 1024);
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

                    cryptofuzz::operation::ECIES_Encrypt op(parameters);
                    op.Serialize(dsOut2);
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
            default:
                goto end;
        }

        fuzzing::datasource::Datasource dsOut(nullptr, 0);

        /* Operation ID */
        dsOut.Put<uint64_t>(operation);

        dsOut.PutData(dsOut2.GetOut());

        /* Modifier */
        dsOut.PutData(std::vector<uint8_t>(0));

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
