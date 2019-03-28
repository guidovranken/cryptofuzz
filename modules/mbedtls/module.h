#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/aria.h>
#include <mbedtls/camellia.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class mbedTLS : public Module {
    private:
        const mbedtls_cipher_info_t* to_mbedtls_cipher_info_t(const component::SymmetricCipherType cipherType) const;
        mbedtls_md_type_t to_mbedtls_md_type_t(const component::DigestType& digestType) const;
    public:
        mbedTLS(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::MAC> OpCMAC(operation::CMAC& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
