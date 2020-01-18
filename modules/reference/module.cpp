#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#if defined(CRYPTOFUZZ_REFERENCE_CITY_O_PATH)
#include <city.h>
#include <citycrc.h>
#endif

extern "C" {
    #include "xxhash/xxhash.h"
}

extern "C" {
    #include "groestl/groestl-cryptofuzz.h"
}

extern "C" {
    #include "whirlpool/nessie.h"
    void NESSIEinit(struct NESSIEstruct * const structpointer);
    void NESSIEadd(const unsigned char * const source, unsigned long sourceBits, struct NESSIEstruct * const structpointer);
    void NESSIEfinalize(struct NESSIEstruct * const structpointer, unsigned char * const result);
}

extern "C" {
    #include "argon2/include/argon2.h"
}

#if 0
extern "C" {
    #include "blake3/blake3.h"
}
#endif

namespace cryptofuzz {
namespace module {

Reference::Reference(void) :
    Module("Reference implementations"),
    haveSSE42(util::HaveSSE42()) {
}

std::optional<component::Digest> Reference::WHIRLPOOL(operation::Digest& op, Datasource& ds) const {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    struct NESSIEstruct nessie;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        NESSIEinit(&nessie);
    }

    /* Process */
    for (const auto& part : parts) {
        NESSIEadd(part.first, part.second * 8, &nessie);
    }

    /* Finalize */
    {
        uint8_t result[64];
        NESSIEfinalize(&nessie, result);
        ret = component::Digest(result, sizeof(result));
    }

    return ret;
}

std::optional<component::Digest> Reference::GROESTL(operation::Digest& op, Datasource& ds, const size_t bitSize) const {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    void* ctx = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(ctx = groestl_init(bitSize), nullptr);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(groestl_update(ctx, part.first, part.second), true);
    }

    /* Finalize */
    {
        uint8_t result[bitSize / 8];
        CF_CHECK_EQ(groestl_final(ctx, result), true);
        ret = component::Digest(result, sizeof(result));
    }

end:
    groestl_free(ctx);

    return ret;
}

std::optional<component::Digest> Reference::XXHASH64_OneShot(operation::Digest& op) const {
    const auto hash = XXH64(op.cleartext.GetPtr(), op.cleartext.GetSize(), 0 /* seed */);
    return component::Digest((const uint8_t*)(&hash), sizeof(hash));
}

std::optional<component::Digest> Reference::XXHASH64_Streaming(operation::Digest& op, Datasource& ds) const {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    XXH64_state_t* state = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(state = XXH64_createState(), nullptr);
        CF_CHECK_NE(XXH64_reset(state, 0 /* seed */), XXH_ERROR);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_NE(XXH64_update(state, part.first, part.second), XXH_ERROR);
    }

    /* Finalize */
    {
        const auto hash = XXH64_digest(state);
        ret = component::Digest((const uint8_t*)(&hash), sizeof(hash));
    }

end:
    XXH64_freeState(state);

    return ret;
}

std::optional<component::Digest> Reference::XXHASH64(operation::Digest& op, Datasource& ds) const {
    bool useOneShot = true;
    try {
        useOneShot = ds.Get<bool>();
    } catch ( ... ) { }

    if ( useOneShot == true ) {
        return XXHASH64_OneShot(op);
    } else {
        return XXHASH64_Streaming(op, ds);
    }
}

std::optional<component::Digest> Reference::XXHASH32_OneShot(operation::Digest& op) const {
    const auto hash = XXH32(op.cleartext.GetPtr(), op.cleartext.GetSize(), 0 /* seed */);
    return component::Digest((const uint8_t*)(&hash), sizeof(hash));
}

std::optional<component::Digest> Reference::XXHASH32_Streaming(operation::Digest& op, Datasource& ds) const {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    XXH32_state_t* state = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(state = XXH32_createState(), nullptr);
        CF_CHECK_NE(XXH32_reset(state, 0 /* seed */), XXH_ERROR);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_NE(XXH32_update(state, part.first, part.second), XXH_ERROR);
    }

    /* Finalize */
    {
        const auto hash = XXH32_digest(state);
        ret = component::Digest((const uint8_t*)(&hash), sizeof(hash));
    }

end:
    XXH32_freeState(state);

    return ret;
}

std::optional<component::Digest> Reference::XXHASH32(operation::Digest& op, Datasource& ds) const {
    bool useOneShot = true;
    try {
        useOneShot = ds.Get<bool>();
    } catch ( ... ) { }

    if ( useOneShot == true ) {
        return XXHASH32_OneShot(op);
    } else {
        return XXHASH32_Streaming(op, ds);
    }
}

#if 0
std::optional<component::Digest> Reference::BLAKE3(operation::Digest& op, Datasource& ds) const {
    std::optional<component::Digest> ret = std::nullopt;

    blake3_hasher hasher;
    util::Multipart parts;
    uint8_t out[BLAKE3_OUT_LEN];

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        /* noret */ blake3_hasher_init(&hasher);
    }

    /* Process */
    for (const auto& part : parts) {
        /* noret */ blake3_hasher_update(&hasher, part.first, part.second);
    }

    /* Finalize */
    {
        /* noret */ blake3_hasher_finalize(&hasher, out, sizeof(out));
        ret = component::Digest(out, sizeof(out));
    }

    return ret;
}

/* Note: this is not an actual HMAC */
std::optional<component::MAC> Reference::BLAKE3_MAC(operation::HMAC& op, Datasource& ds) const {
    std::optional<component::MAC> ret = std::nullopt;

    blake3_hasher hasher;
    util::Multipart parts;
    uint8_t out[BLAKE3_OUT_LEN];

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.key.GetSize(), BLAKE3_KEY_LEN);
        parts = util::ToParts(ds, op.cleartext);
        /* noret */ blake3_hasher_init_keyed(&hasher, op.cipher.key.GetPtr());
    }

    /* Process */
    for (const auto& part : parts) {
        /* noret */ blake3_hasher_update(&hasher, part.first, part.second);
    }

    /* Finalize */
    {
        /* noret */ blake3_hasher_finalize(&hasher, out, sizeof(out));
        ret = component::MAC(out, sizeof(out));
    }

end:
    return ret;
}
#endif

std::optional<component::Digest> Reference::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
#if defined(CRYPTOFUZZ_REFERENCE_CITY_O_PATH)
        case CF_DIGEST("CITYHASH32"):
            {
                const auto res = CityHash32((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                /* TODO endianness */
                ret = component::Digest((const uint8_t*)&res, sizeof(res));
            }
            break;
        case CF_DIGEST("CITYHASH64"):
            {
                const auto res = CityHash64((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                /* TODO endianness */
                ret = component::Digest((const uint8_t*)&res, sizeof(res));
            }
            break;
        case CF_DIGEST("CITYHASH128"):
            {
                const auto res = CityHash128((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                /* TODO endianness */
                ret = component::Digest((const uint8_t*)&res, sizeof(res));
            }
            break;
        case CF_DIGEST("CITYHASHCRC128"):
            {
                /* CityHashCrc128 is not compiled on 32 bit */
#if defined(__x86_64__) || defined(_M_X64)
                if ( haveSSE42 == true ) {
                    const auto res = CityHashCrc128((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                    /* TODO endianness */
                    ret = component::Digest((const uint8_t*)&res, sizeof(res));
                }
#endif
            }
            break;
        case CF_DIGEST("CITYHASHCRC256"):
            {
/* CityHashCrc256 is not compiled on 32 bit */
#if defined(__x86_64__) || defined(_M_X64)
                if ( haveSSE42 ) {
                    uint64_t out[4];

                    /* Don't output into an uint8_t array directory, to prevent alignment violations */
                    /* noret */ CityHashCrc256((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize(), out);

                    /* uint64_t[4] -> uint8_t[] */
                    uint8_t outBytes[sizeof(out)];
                    for (size_t i = 0; i < 4; i++) {
                        memcpy(outBytes + i * sizeof(uint64_t), &(out[i]), sizeof(uint64_t));
                    }

                    /* TODO endianness */
                    ret = component::Digest(outBytes, sizeof(outBytes));
                }
#endif
            }
            break;
#endif /* CRYPTOFUZZ_REFERENCE_CITY_O_PATH */
        case CF_DIGEST("GROESTL_224"):
            {
                return GROESTL(op, ds, 224);
            }
            break;
        case CF_DIGEST("GROESTL_256"):
            {
                return GROESTL(op, ds, 256);
            }
            break;
        case CF_DIGEST("GROESTL_384"):
            {
                return GROESTL(op, ds, 384);
            }
            break;
        case CF_DIGEST("GROESTL_512"):
            {
                return GROESTL(op, ds, 512);
            }
            break;
        case CF_DIGEST("WHIRLPOOL"):
            {
                return WHIRLPOOL(op, ds);
            }
            break;
        case CF_DIGEST("XXHASH64"):
            {
                return XXHASH64(op, ds);
            }
            break;
        case CF_DIGEST("XXHASH32"):
            {
                return XXHASH32(op, ds);
            }
            break;
#if 0
        case CF_DIGEST("BLAKE3"):
            {
                return BLAKE3(op, ds);
            }
            break;
#endif
    }

    return ret;
}

std::optional<component::MAC> Reference::OpHMAC(operation::HMAC& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
#if defined(CRYPTOFUZZ_REFERENCE_CITY_O_PATH)
        /* Note: Cityhash + seed is not actually a HMAC, but it is convenient here to use it as such */
        case CF_DIGEST("CITYHASH64SEED8"):
            {
                uint64_t seed;
                if ( op.cipher.key.GetSize() == sizeof(seed) ) {
                    memcpy(&seed, op.cipher.key.GetPtr(), sizeof(seed));

                    const auto res = CityHash64WithSeed((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize(), seed);
                    /* TODO endianness */
                    ret = component::Digest((const uint8_t*)&res, sizeof(res));
                }
            }
            break;
        case CF_DIGEST("CITYHASH64SEED16"):
            {
                uint64_t seed1, seed2;
                if ( op.cipher.key.GetSize() == sizeof(seed1) + sizeof(seed2) ) {
                    memcpy(&seed1, op.cipher.key.GetPtr(), sizeof(seed1));
                    memcpy(&seed2, op.cipher.key.GetPtr() + sizeof(seed1), sizeof(seed2));

                    const auto res = CityHash64WithSeeds((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize(), seed1, seed2);
                    /* TODO endianness */
                    ret = component::Digest((const uint8_t*)&res, sizeof(res));
                }
            }
            break;
        case CF_DIGEST("CITYHASH128SEED16"):
            {
                if ( haveSSE42 == true ) {
                    uint128 seed;
                    if ( op.cipher.key.GetSize() == sizeof(seed) ) {
                        memcpy(&seed, op.cipher.key.GetPtr(), sizeof(seed));

                        const auto res = CityHash128WithSeed((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize(), seed);
                        /* TODO endianness */
                        ret = component::Digest((const uint8_t*)&res, sizeof(res));
                    }
                }
            }
            break;
        case CF_DIGEST("CITYHASHCRC128SEED16"):
            {
/* CityHashCrc128WithSeed is not compiled on 32 bit */
#if defined(__x86_64__) || defined(_M_X64)
                if ( haveSSE42 == true ) {
                    uint128 seed;
                    if ( op.cipher.key.GetSize() == sizeof(seed) ) {
                        memcpy(&seed, op.cipher.key.GetPtr(), sizeof(seed));

                        const auto res = CityHashCrc128WithSeed((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize(), seed);
                        /* TODO endianness */
                        ret = component::Digest((const uint8_t*)&res, sizeof(res));
                    }
                }
#endif
            }
            break;
#endif
#if 0
        case CF_DIGEST("BLAKE3"):
            {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                return BLAKE3_MAC(op, ds);
            }
            break;
#endif
    }

    return ret;
}

std::optional<component::Key> Reference::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    uint8_t* out = util::malloc(op.keySize);

    argon2_type type;
    switch ( op.type ) {
        case    0:
            type = Argon2_d;
            break;
        case    1:
            type = Argon2_i;
            break;
        case    2:
            type = Argon2_id;
            break;
        default:
            goto end;
    }

    CF_CHECK_LTE(op.threads, 32);
#if 0
    CF_CHECK_EQ(argon2_hash(
                op.iterations,
                op.memory,
                op.threads,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                out,
                op.keySize,
                nullptr,
                0,
                type,
                ARGON2_VERSION_13
        ), ARGON2_OK);

    ret = component::Key(out, op.keySize);
#endif

end:
    util::free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
