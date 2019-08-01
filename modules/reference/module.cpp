#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#if defined(CRYPTOFUZZ_REFERENCE_CITY_O_PATH)
#include <city.h>
#include <citycrc.h>
#endif

extern "C" {
    #include "groestl/groestl-cryptofuzz.h"
}

extern "C" {
    #include "whirlpool/nessie.h"
    void NESSIEinit(struct NESSIEstruct * const structpointer);
    void NESSIEadd(const unsigned char * const source, unsigned long sourceBits, struct NESSIEstruct * const structpointer);
    void NESSIEfinalize(struct NESSIEstruct * const structpointer, unsigned char * const result);
}

namespace cryptofuzz {
namespace module {

Reference::Reference(void) :
    Module("Reference implementations") { }

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
                bool useCrcMethod = false;
                try {
                    /* Always get the bool, so the structure of the input file is retained */
#ifdef __SSE4_2__
                    useCrcMethod =
#endif
                        ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) {
                }

                if ( useCrcMethod == false ) {
                    const auto res = CityHash128((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                    /* TODO endianness */
                    ret = component::Digest((const uint8_t*)&res, sizeof(res));
                } else {
/* CityHashCrc128 is not compiled if __SSE4_2__ is undefined */
#ifdef __SSE4_2__
                    const auto res = CityHashCrc128((const char*)op.cleartext.GetPtr(), op.cleartext.GetSize());
                    /* TODO endianness */
                    ret = component::Digest((const uint8_t*)&res, sizeof(res));
#else
                    /* This should never happen */
                    abort();
#endif /* __SSE4_2__ */
                }
            }
            break;
/* CityHashCrc256 is not compiled if __SSE4_2__ is undefined */
#ifdef __SSE4_2__
        case CF_DIGEST("CITYHASH256"):
            {
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
            break;
#endif /* __SSE4_2__ */
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
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
