#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Veracrypt : public Module {
    private:
        std::optional<component::Ciphertext> kuznyechik(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> kuznyechik(operation::SymmetricDecrypt& op) const;
        std::optional<component::Ciphertext> GOST_28147_89(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> GOST_28147_89(operation::SymmetricDecrypt& op) const;
        std::optional<component::Ciphertext> twofish(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> twofish(operation::SymmetricDecrypt& op) const;
        std::optional<component::Ciphertext> serpent(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> serpent(operation::SymmetricDecrypt& op) const;
        std::optional<component::Ciphertext> aes(operation::SymmetricEncrypt& op) const;
        std::optional<component::Cleartext> aes(operation::SymmetricDecrypt& op) const;
        std::optional<component::Ciphertext> chacha20(operation::SymmetricEncrypt& op) const;
    public:
        Veracrypt(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
