#pragma once

#include <cryptofuzz/module.h>
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

        using ResultPair = std::pair< std::shared_ptr<Module>, std::optional<ResultType> >;
        using ResultSet = std::vector<ResultPair>;

        ResultSet filter(const ResultSet& results) const;
        void compare(const ResultSet& results, const uint8_t* data, const size_t size) const;
        OperationType getOp(Datasource* parentDs, const uint8_t* data, const size_t size) const;
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

    public:
        void Run(Datasource& parentDs, const uint8_t* data, const size_t size) const;
        ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules);
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
using ExecutorKDF_PBKDF2 = ExecutorBase<component::Key, operation::KDF_PBKDF2>;
using ExecutorSign = ExecutorBase<component::Signature, operation::Sign>;
using ExecutorVerify = ExecutorBase<bool, operation::Verify>;

} /* namespace cryptofuzz */
