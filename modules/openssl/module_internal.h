#pragma once

namespace cryptofuzz {
namespace module {

class CF_EVP_CIPHER_CTX {
    private:
        EVP_CIPHER_CTX* ctx = nullptr;
        Datasource& ds;
        
        EVP_CIPHER_CTX* copy(void) {
            bool doCopyCTX = true;
            try {
                doCopyCTX = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

            if ( doCopyCTX == true ) {
                EVP_CIPHER_CTX* tmpCtx = EVP_CIPHER_CTX_new();
                if ( tmpCtx != nullptr ) {
                    if ( EVP_CIPHER_CTX_copy(tmpCtx, ctx) == 1 ) {
                        /* Copy succeeded, free the old ctx */
                        EVP_CIPHER_CTX_free(ctx);

                        /* Use the copied ctx */
                        ctx = tmpCtx;
                    } else {
                        EVP_CIPHER_CTX_free(tmpCtx);
                    }
                }
            }

            return ctx;
        }

    public:
        CF_EVP_CIPHER_CTX(Datasource& ds) :
            ds(ds) {
            ctx = EVP_CIPHER_CTX_new();
            if ( ctx == nullptr ) {
                abort();
            }
        }

        EVP_CIPHER_CTX* GetPtr(void) {
            return copy();
        }

        ~CF_EVP_CIPHER_CTX() {
            EVP_CIPHER_CTX_free(ctx);
        }
};

} /* namespace module */
} /* namespace cryptofuzz */
