#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mbedtls/platform.h>
#include <psa/crypto.h>

namespace cryptofuzz {
namespace module {

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
    Module("PSA Crypto") {

    if ( mbedtls_platform_set_calloc_free(mbedTLS_custom_calloc, mbedTLS_custom_free) != 0 ) {
        abort();
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        /* The most plausible error cause here is that Mbed TLS is compiled
         * with MBEDTLS_ENTROPY_NV_SEED enabled and the entropy seed file
         * is missing. If so, create a 64-byte file called "seedfile" in
         * the current directory. */
        abort();
    }
}

TF_PSA_Crypto::~TF_PSA_Crypto(void)
{
    mbedtls_psa_crypto_free();
}


} /* namespace module */
} /* namespace cryptofuzz */
