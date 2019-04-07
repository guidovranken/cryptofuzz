#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Bitcoin : public Module {
    private:
        template <class Alg> std::optional<component::Digest> digest(operation::Digest& op, Datasource& ds);
        template <class Alg> std::optional<component::MAC> hmac(operation::HMAC& op, Datasource& ds);
    public:
        Bitcoin(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
