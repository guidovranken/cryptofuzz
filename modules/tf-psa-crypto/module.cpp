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

    class HashOperation {
        psa_hash_operation_t operation;

    public:
        HashOperation() {
            operation = PSA_HASH_OPERATION_INIT;
        }
        ~HashOperation() {
            psa_hash_abort(&operation);
        }

        psa_status_t setup(psa_algorithm_t alg) {
            return psa_hash_setup(&operation, alg);
        }
        psa_status_t update(const unsigned char *input, size_t input_length) {
            return psa_hash_update(&operation, input, input_length);
        }
        psa_status_t finish(unsigned char *output, size_t output_size,
                            size_t *output_length) {
            return psa_hash_finish(&operation, output, output_size, output_length);
        }
        psa_status_t verify(const unsigned char *hash, size_t hash_length) {
            return psa_hash_verify(&operation, hash, hash_length);
        }
    };

}

static std::optional<component::Digest> hash_compute(operation::Digest& op,
                                                     Datasource &ds,
                                                     psa_algorithm_t alg) {
    std::vector<uint8_t> md(PSA_HASH_LENGTH(alg));
    size_t length = 0;
    bool const multipart = ds.Get<bool>();
    if (multipart) {
        TF_PSA_Crypto_detail::HashOperation operation;
        /* Initialize */
        util::Multipart parts = util::ToParts(ds, op.cleartext);
        CF_ASSERT_PSA(operation.setup(alg));

        /* Process */
        for (const auto& part : parts) {
            CF_ASSERT_PSA(operation.update(part.first, part.second));
        }

        /* Finalize */
        CF_ASSERT_PSA(operation.finish(md.data(), md.size(), &length));
    } else {
        /* One-shot computation */
        CF_ASSERT_PSA(psa_hash_compute(alg,
                                       op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                                       md.data(), md.size(), &length));
    }
    return component::Digest(md.data(), length);
}

std::optional<component::Digest> TF_PSA_Crypto::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    TF_PSA_Crypto_detail::SetGlobalDs(&ds);

    psa_algorithm_t const alg =
        TF_PSA_Crypto_detail::to_psa_algorithm_t(op.digestType);
    /* Skip unknown algorithms */
    CF_CHECK_NE(alg, PSA_ALG_NONE);

    ret = hash_compute(op, ds, alg);

end:
    TF_PSA_Crypto_detail::UnsetGlobalDs();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
