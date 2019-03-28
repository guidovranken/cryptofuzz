#pragma once

#include <string>
#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <fuzzing/datasource/id.hpp>
#include <optional>

namespace cryptofuzz {

class Module {
    public:
        const std::string name;
        const uint64_t ID;

        Module(const std::string name) :
            name(name),
            ID(fuzzing::datasource::ID( ("Cryptofuzz/Module/" + name).c_str()))
        { }

        virtual ~Module() { }

        virtual std::optional<component::Digest> OpDigest(operation::Digest& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::MAC> OpHMAC(operation::HMAC& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Key> OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Key> OpKDF_HKDF(operation::KDF_HKDF& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Key> OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Key> OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::MAC> OpCMAC(operation::CMAC& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Signature> OpSign(operation::Sign& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<bool> OpVerify(operation::Verify& op) {
            (void)op;
            return std::nullopt;
        }
};

} /* namespace cryptofuzz */
