#pragma once

#include <cryptofuzz/module.h>
#include <cryptofuzz/options.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace cryptofuzz {

template <class ResultType, class OperationType>
class ExecutorBase {
    private:
        const uint64_t operationID;
        const std::map<uint64_t, std::shared_ptr<Module> > modules;
        const Options& options;

        using ResultPair = std::pair< std::shared_ptr<Module>, std::optional<ResultType> >;
        using ResultSet = std::vector<ResultPair>;

        ResultSet filter(const ResultSet& results) const;
        bool dontCompare(const OperationType& operation) const;
        void compare(const std::vector< std::pair<std::shared_ptr<Module>, OperationType> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const;
        OperationType getOp(Datasource* parentDs, const uint8_t* data, const size_t size) const;
        OperationType getOpPostprocess(Datasource* parentDs, OperationType op) const;
        std::shared_ptr<Module> getModule(Datasource& ds) const;
        void updateExtraCounters(
                const uint64_t moduleID,
                const uint64_t operation,
                const uint64_t operationDetail0 = 0,
                const uint64_t operationDetail1 = 0,
                const uint64_t operationDetail2 = 0) const;

        /* To be implemented by specializations of ExecutorBase */
        void updateExtraCounters(const uint64_t moduleID, OperationType& op) const;
        void postprocess(std::shared_ptr<Module> module, OperationType& op, const ResultPair& result) const;
        std::optional<ResultType> callModule(std::shared_ptr<Module> module, OperationType& op) const;

        void abort(std::vector<std::string> moduleNames, const std::string operation, const std::string algorithm, const std::string reason) const;
    public:
        void Run(Datasource& parentDs, const uint8_t* data, const size_t size) const;
        ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options);
        virtual ~ExecutorBase();
};

/* Declare aliases */
using ExecutorDigest = ExecutorBase<component::Digest, operation::Digest>;
using ExecutorHMAC = ExecutorBase<component::MAC, operation::HMAC>;
using ExecutorCMAC = ExecutorBase<component::MAC, operation::CMAC>;
using ExecutorSymmetricEncrypt = ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>;
using ExecutorSymmetricDecrypt = ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>;
using ExecutorKDF_SCRYPT = ExecutorBase<component::Key, operation::KDF_SCRYPT>;
using ExecutorKDF_HKDF = ExecutorBase<component::Key, operation::KDF_HKDF>;
using ExecutorKDF_TLS1_PRF = ExecutorBase<component::Key, operation::KDF_TLS1_PRF>;
using ExecutorKDF_PBKDF = ExecutorBase<component::Key, operation::KDF_PBKDF>;
using ExecutorKDF_PBKDF1 = ExecutorBase<component::Key, operation::KDF_PBKDF1>;
using ExecutorKDF_PBKDF2 = ExecutorBase<component::Key, operation::KDF_PBKDF2>;
using ExecutorKDF_ARGON2 = ExecutorBase<component::Key, operation::KDF_ARGON2>;
using ExecutorKDF_SSH = ExecutorBase<component::Key, operation::KDF_SSH>;
using ExecutorKDF_X963 = ExecutorBase<component::Key, operation::KDF_X963>;
using ExecutorKDF_BCRYPT = ExecutorBase<component::Key, operation::KDF_BCRYPT>;
using ExecutorKDF_SP_800_108 = ExecutorBase<component::Key, operation::KDF_SP_800_108>;
using ExecutorSign = ExecutorBase<component::Signature, operation::Sign>;
using ExecutorVerify = ExecutorBase<bool, operation::Verify>;
using ExecutorECC_PrivateToPublic = ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>;
using ExecutorECC_GenerateKeyPair = ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>;
using ExecutorECDSA_Sign = ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>;
using ExecutorECDSA_Verify = ExecutorBase<bool, operation::ECDSA_Verify>;
using ExecutorECDH_Derive = ExecutorBase<component::Secret, operation::ECDH_Derive>;
using ExecutorBignumCalc = ExecutorBase<component::Bignum, operation::BignumCalc>;

} /* namespace cryptofuzz */
