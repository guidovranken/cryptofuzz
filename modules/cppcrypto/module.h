#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>
#include <cppcrypto/cbc.h>
#include <cppcrypto/ctr.h>

namespace cryptofuzz {
namespace module {

class CPPCrypto : public Module {
    private:
        template <class Hasher> std::optional<component::Digest> digest(Hasher& hasher, operation::Digest& op, Datasource& ds, size_t hashSize = 0) const;

        std::optional<component::Ciphertext> encryptCBC(cppcrypto::cbc& cbc, operation::SymmetricEncrypt& op, Datasource& ds) const;
        std::optional<component::Cleartext> decryptCBC(cppcrypto::cbc& cbc, operation::SymmetricDecrypt& op, Datasource& ds) const;

        std::optional<component::Ciphertext> encryptCTR(cppcrypto::ctr& ctr, operation::SymmetricEncrypt& op, Datasource& ds, const size_t keySize, const size_t blockSize) const;
        std::optional<component::Ciphertext> decryptCTR(cppcrypto::ctr& ctr, operation::SymmetricDecrypt& op, Datasource& ds, const size_t keySize, const size_t blockSize) const;
        std::optional<component::Cleartext> decryptCTR(cppcrypto::ctr& ctr, operation::SymmetricDecrypt& op, Datasource& ds) const;
    public:
        CPPCrypto(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
        std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) override;
        std::optional<component::Cleartext> OpSymmetricDecrypt(operation::SymmetricDecrypt& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
