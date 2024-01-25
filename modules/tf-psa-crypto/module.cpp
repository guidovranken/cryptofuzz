#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mbedtls/platform.h>
#include <psa/crypto.h>

namespace cryptofuzz {
namespace module {

#define CF_ASSERT_PSA(expr) CF_ASSERT_EQ(expr, PSA_SUCCESS)

namespace TF_PSA_Crypto_detail {
    Datasource* ds;

    inline void SetGlobalDs(Datasource* ds) {
        TF_PSA_Crypto_detail::ds = ds;
    }

    inline void UnsetGlobalDs(void) {
        TF_PSA_Crypto_detail::ds = nullptr;
    }

    inline bool AllocationFailure(void) {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
        bool fail = false;
        if ( ds == nullptr ) {
            return fail;
        }
        try {
            fail = ds->Get<bool>();
        } catch ( ... ) { }

        return fail;
#else
        return false;
#endif
    }
}

static void* mbedTLS_custom_calloc(size_t A, size_t B) {
    if ( TF_PSA_Crypto_detail::AllocationFailure() == true ) {
        return nullptr;
    }

    /* TODO detect overflows */
    const size_t size = A*B;
    void* p = util::malloc(size);
    if ( size ) {
        memset(p, 0x00, size);
    }
    return p;
}

static void mbedTLS_custom_free(void* ptr) {
    util::free(ptr);
}

TF_PSA_Crypto::TF_PSA_Crypto(void) :
    Module("PSA-Crypto") {

    if ( mbedtls_platform_set_calloc_free(mbedTLS_custom_calloc, mbedTLS_custom_free) != 0 ) {
        abort();
    }

    /* The most plausible error cause here is that Mbed TLS is compiled
     * with MBEDTLS_ENTROPY_NV_SEED enabled and the entropy seed file is
     * missing. To fix that problem, create a 64-byte file called "seedfile"
     * in the current directory. */
    CF_ASSERT_PSA(psa_crypto_init());
}

TF_PSA_Crypto::~TF_PSA_Crypto(void)
{
    mbedtls_psa_crypto_free();
}

namespace TF_PSA_Crypto_detail {

    psa_algorithm_t to_psa_algorithm_t(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, psa_algorithm_t> LUT = {
            { CF_DIGEST("MD5"), PSA_ALG_MD5 },
            { CF_DIGEST("RIPEMD160"), PSA_ALG_RIPEMD160 },
            { CF_DIGEST("SHA1"), PSA_ALG_SHA_1 },
            { CF_DIGEST("SHA224"), PSA_ALG_SHA_224 },
            { CF_DIGEST("SHA256"), PSA_ALG_SHA_256 },
            { CF_DIGEST("SHA384"), PSA_ALG_SHA_384 },
            { CF_DIGEST("SHA512"), PSA_ALG_SHA_512 },
            { CF_DIGEST("SHA3-224"), PSA_ALG_SHA3_224 },
            { CF_DIGEST("SHA3-256"), PSA_ALG_SHA3_256 },
            { CF_DIGEST("SHA3-384"), PSA_ALG_SHA3_384 },
            { CF_DIGEST("SHA3-512"), PSA_ALG_SHA3_512 },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return PSA_ALG_NONE;
        }

        return LUT.at(digestType.Get());
    }

}

std::optional<component::Digest> TF_PSA_Crypto::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    bool multipart = ds.Get<bool>();
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    {
        psa_algorithm_t alg = PSA_ALG_NONE;
        /* Skip unknown algorithms */
        CF_CHECK_NE(alg = TF_PSA_Crypto_detail::to_psa_algorithm_t(op.digestType), PSA_ALG_NONE);

        unsigned char md[PSA_HASH_LENGTH(alg)];
        size_t length = 0;

        if (multipart) {
            /* Initialize */
            util::Multipart parts = util::ToParts(ds, op.cleartext);
            CF_ASSERT_PSA(psa_hash_setup(&operation, alg));

            /* Process */
            for (const auto& part : parts) {
                CF_ASSERT_PSA(psa_hash_update(&operation, part.first, part.second));
            }

            /* Finalize */
            CF_ASSERT_PSA(psa_hash_finish(&operation, md, sizeof(md), &length));
        } else {
            /* One-shot computation */
            CF_ASSERT_PSA(psa_hash_compute(alg,
                                           op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                                           md, sizeof(md), &length));
        }

        ret = component::Digest(md, length);
    }

end:
    psa_hash_abort(&operation);

    TF_PSA_Crypto_detail::UnsetGlobalDs();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
