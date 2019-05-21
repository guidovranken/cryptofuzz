#pragma once

namespace cryptofuzz {
namespace module {

template <class T>
class CTX_Copier {
    private:
        T* ctx = nullptr;
        Datasource& ds;

        T* newCTX(void) const;
        int copyCTX(T* dest, T* src) const;
        void freeCTX(T* ctx) const;

        T* copy(void) {
            bool doCopyCTX = true;
            try {
                doCopyCTX = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            if ( doCopyCTX == true ) {
                T* tmpCtx = newCTX();
                if ( tmpCtx != nullptr ) {
                    if ( copyCTX(tmpCtx, ctx) == 1 ) {
                        /* Copy succeeded, free the old ctx */
                        freeCTX(ctx);

                        /* Use the copied ctx */
                        ctx = tmpCtx;
                    } else {
                        freeCTX(tmpCtx);
                    }
                }
            }

            return ctx;
        }

    public:
        CTX_Copier(Datasource& ds) :
            ds(ds) {
            ctx = newCTX();
            if ( ctx == nullptr ) {
                abort();
            }
        }

        T* GetPtr(void) {
            return copy();
        }

        ~CTX_Copier() {
            freeCTX(ctx);
        }
};

#if !defined(CRYPTOFUZZ_OPENSSL_102)
template<> EVP_MD_CTX* CTX_Copier<EVP_MD_CTX>::newCTX(void) const { return EVP_MD_CTX_new(); }
#else
template<> EVP_MD_CTX* CTX_Copier<EVP_MD_CTX>::newCTX(void) const {
    EVP_MD_CTX* ret = (EVP_MD_CTX*)malloc(sizeof(*ret));
    EVP_MD_CTX_init(ret);
    return ret;
}
#endif

template<> int CTX_Copier<EVP_MD_CTX>::copyCTX(EVP_MD_CTX* dest, EVP_MD_CTX* src) const { return EVP_MD_CTX_copy(dest, src); }

#if !defined(CRYPTOFUZZ_OPENSSL_102)
template<> void CTX_Copier<EVP_MD_CTX>::freeCTX(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
#else
template<> void CTX_Copier<EVP_MD_CTX>::freeCTX(EVP_MD_CTX* ctx) const { EVP_MD_CTX_cleanup(ctx); free(ctx); }
#endif

template<> EVP_CIPHER_CTX* CTX_Copier<EVP_CIPHER_CTX>::newCTX(void) const { return EVP_CIPHER_CTX_new(); }
template<> int CTX_Copier<EVP_CIPHER_CTX>::copyCTX(EVP_CIPHER_CTX* dest, EVP_CIPHER_CTX* src) const { return EVP_CIPHER_CTX_copy(dest, src); }
template<> void CTX_Copier<EVP_CIPHER_CTX>::freeCTX(EVP_CIPHER_CTX* ctx) const { return EVP_CIPHER_CTX_free(ctx); }

#if !defined(CRYPTOFUZZ_OPENSSL_102)
template<> HMAC_CTX* CTX_Copier<HMAC_CTX>::newCTX(void) const { return HMAC_CTX_new(); }
template<> int CTX_Copier<HMAC_CTX>::copyCTX(HMAC_CTX* dest, HMAC_CTX* src) const { return HMAC_CTX_copy(dest, src); }
template<> void CTX_Copier<HMAC_CTX>::freeCTX(HMAC_CTX* ctx) const { return HMAC_CTX_free(ctx); }
#endif

template<> CMAC_CTX* CTX_Copier<CMAC_CTX>::newCTX(void) const { return CMAC_CTX_new(); }
template<> int CTX_Copier<CMAC_CTX>::copyCTX(CMAC_CTX* dest, CMAC_CTX* src) const { return CMAC_CTX_copy(dest, src); }
template<> void CTX_Copier<CMAC_CTX>::freeCTX(CMAC_CTX* ctx) const { return CMAC_CTX_free(ctx); }

using CF_EVP_MD_CTX = CTX_Copier<EVP_MD_CTX>;
using CF_EVP_CIPHER_CTX = CTX_Copier<EVP_CIPHER_CTX>;
using CF_HMAC_CTX = CTX_Copier<HMAC_CTX>;
using CF_CMAC_CTX = CTX_Copier<CMAC_CTX>;
} /* namespace module */
} /* namespace cryptofuzz */
