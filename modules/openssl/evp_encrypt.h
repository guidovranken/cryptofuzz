#pragma once

#include <openssl/evp.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/operations.h>
#include "module_internal.h"

namespace cryptofuzz {
namespace module {
namespace OpenSSL_detail {

class SymmetricEncrypt_EVP {
    private:
        operation::SymmetricEncrypt& op;
        fuzzing::datasource::Datasource& ds;

        const EVP_CIPHER* cipher = nullptr;
        CF_EVP_CIPHER_CTX ctx;

        bool ctxInitializedOnce = false;
        std::vector<uint8_t> cleartext;
        util::Multipart partsCleartext, partsAAD;
        size_t outSize, outIdx;
        uint8_t* out = nullptr;
        uint8_t* outTag = nullptr;

        void triggerReinitialize(void) const;

        bool initialize_parts(void);
        bool initialize_EVP_1(void);
        bool initialize_EVP_2(void);
        bool prepare_IV(void);
        bool prepare_key(void);
        bool set_IV_key(void);
        bool set_padding(void);
        bool prepare_CCM(void);
        bool set_AAD(void);
        bool encrypt(void);
        std::optional<component::Ciphertext> finalize(void);
    public:
        SymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, fuzzing::datasource::Datasource& ds);
        std::optional<component::Ciphertext> Run(void);
};

} /* namespace OpenSSL_detail */
} /* namespace module */
} /* namespace cryptofuzz */
