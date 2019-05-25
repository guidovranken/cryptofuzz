#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>

extern "C" {
#include <portable/EverCrypt_AutoConfig2.h>
#include <portable/EverCrypt_Hash.h>
#include <portable/EverCrypt_Hash_Incremental.h>
#include <portable/EverCrypt_HMAC.h>
#include <portable/EverCrypt_HKDF.h>
#include <portable/EverCrypt_AEAD.h>
}

namespace cryptofuzz {
namespace module {

class EverCrypt : public Module {
    private:
        std::optional<component::Digest> MD5(operation::Digest& op) const;
        std::optional<component::Digest> SHA1(operation::Digest& op) const;
        std::optional<component::Digest> SHA224(operation::Digest& op) const;
        std::optional<component::Digest> SHA256(operation::Digest& op) const;
        std::optional<component::Digest> SHA384(operation::Digest& op) const;
        std::optional<component::Digest> SHA512(operation::Digest& op) const;

        std::optional<component::MAC> HMAC(Spec_Hash_Definitions_hash_alg alg, uint32_t mac_len, operation::HMAC& op) const;
        std::optional<component::Key> HKDF(Spec_Hash_Definitions_hash_alg alg, uint32_t hash_len, operation::KDF_HKDF& op) const;

    public:
        EverCrypt(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
