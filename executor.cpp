#include "executor.h"
#include "tests.h"
#include <cryptofuzz/util.h>
#include <fuzzing/memory.hpp>

extern "C" {
//__attribute__((section("__libfuzzer_extra_counters")))
struct {
    uint64_t moduleID;
    uint64_t operation;
    uint64_t operationDetail[3];
} extraCounterData;
}

namespace cryptofuzz {

/* Specialization for operation::Digest */
template<> void ExecutorBase<component::Digest, operation::Digest>::updateExtraCounters(const uint64_t moduleID, operation::Digest& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.digestType.Get());
}

template<> void ExecutorBase<component::Digest, operation::Digest>::postprocess(std::shared_ptr<Module> module, operation::Digest& op, const ExecutorBase<component::Digest, operation::Digest>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Digest> ExecutorBase<component::Digest, operation::Digest>::callModule(std::shared_ptr<Module> module, operation::Digest& op) const {
    return module->OpDigest(op);
}

/* Specialization for operation::HMAC */
template<> void ExecutorBase<component::MAC, operation::HMAC>::updateExtraCounters(const uint64_t moduleID, operation::HMAC& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.digestType.Get(), op.cipher.cipherType.Get());
}

template<> void ExecutorBase<component::MAC, operation::HMAC>::postprocess(std::shared_ptr<Module> module, operation::HMAC& op, const ExecutorBase<component::MAC, operation::HMAC>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::HMAC>::callModule(std::shared_ptr<Module> module, operation::HMAC& op) const {
    return module->OpHMAC(op);
}

/* Specialization for operation::CMAC */
template<> void ExecutorBase<component::MAC, operation::CMAC>::updateExtraCounters(const uint64_t moduleID, operation::CMAC& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.cipher.cipherType.Get());
}

template<> void ExecutorBase<component::MAC, operation::CMAC>::postprocess(std::shared_ptr<Module> module, operation::CMAC& op, const ExecutorBase<component::MAC, operation::CMAC>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::CMAC>::callModule(std::shared_ptr<Module> module, operation::CMAC& op) const {
    return module->OpCMAC(op);
}

/* Specialization for operation::SymmetricEncrypt */
template<> void ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::updateExtraCounters(const uint64_t moduleID, operation::SymmetricEncrypt& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.cipher.cipherType.Get(), op.cipher.iv.Get().size());
}

template<> void ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::postprocess(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op, const ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::ResultPair& result) const {
    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }

    if ( op.cleartext.GetSize() > 0 && result.second != std::nullopt && result.second->GetSize() > 0 ) {
        using fuzzing::datasource::ID;

        bool tryDecrypt = true;

        switch ( op.cipher.cipherType.Get() ) {
            case    ID("Cryptofuzz/Cipher/AES_128_OCB"):

            case    ID("Cryptofuzz/Cipher/AES_128_GCM"):
            case    ID("Cryptofuzz/Cipher/AES_192_GCM"):
            case    ID("Cryptofuzz/Cipher/AES_256_GCM"):

            case    ID("Cryptofuzz/Cipher/AES_128_CCM"):
            case    ID("Cryptofuzz/Cipher/AES_192_CCM"):
            case    ID("Cryptofuzz/Cipher/AES_256_CCM"):

            case    ID("Cryptofuzz/Cipher/ARIA_128_CCM"):
            case    ID("Cryptofuzz/Cipher/ARIA_192_CCM"):
            case    ID("Cryptofuzz/Cipher/ARIA_256_CCM"):

            case    ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
            case    ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
            case    ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
                tryDecrypt = false;
                break;
        }

        if ( tryDecrypt == true ) {
            /* Try to decrypt the encrypted data */

            /* Construct a SymmetricDecrypt instance with the SymmetricEncrypt instance */
            auto opDecrypt = operation::SymmetricDecrypt(
                    /* The SymmetricEncrypt instance */
                    op,

                    /* The ciphertext generated by OpSymmetricEncrypt */
                    *(result.second),

                    /* The size of the output buffer that OpSymmetricDecrypt() must use. */
                    op.cleartext.GetSize() + 32,

                    /* Empty modifier */
                    {});

            const auto cleartext = module->OpSymmetricDecrypt(opDecrypt);

            if ( cleartext == std::nullopt ) {
                /* Decryption failed, OpSymmetricDecrypt() returned std::nullopt */
                printf("Cannot decrypt ciphertext\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->Get()).c_str());
                abort();
            } else if ( cleartext->Get() != op.cleartext.Get() ) {
                /* Decryption ostensibly succeeded, but the cleartext returned by OpSymmetricDecrypt()
                 * does not match to original cleartext */

                printf("Cannot decrypt ciphertext (but decryption ostensibly succeeded)\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->Get()).c_str());
                printf("Purported cleartext: %s\n", util::HexDump(cleartext->Get()).c_str());
                abort();
            }
        }
    }
}

template<> std::optional<component::Cleartext> ExecutorBase<component::Cleartext, operation::SymmetricEncrypt>::callModule(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op) const {
    return module->OpSymmetricEncrypt(op);
}

/* Specialization for operation::SymmetricDecrypt */
template<> void ExecutorBase<component::MAC, operation::SymmetricDecrypt>::updateExtraCounters(const uint64_t moduleID, operation::SymmetricDecrypt& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.ciphertext.Get().size(), op.cipher.cipherType.Get());
}

template<> void ExecutorBase<component::MAC, operation::SymmetricDecrypt>::postprocess(std::shared_ptr<Module> module, operation::SymmetricDecrypt& op, const ExecutorBase<component::MAC, operation::SymmetricDecrypt>::ResultPair& result) const {
    (void)module;
    (void)op;
    
    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::MAC> ExecutorBase<component::MAC, operation::SymmetricDecrypt>::callModule(std::shared_ptr<Module> module, operation::SymmetricDecrypt& op) const {
    return module->OpSymmetricDecrypt(op);
}

/* Specialization for operation::KDF_SCRYPT */
template<> void ExecutorBase<component::Key, operation::KDF_SCRYPT>::updateExtraCounters(const uint64_t moduleID, operation::KDF_SCRYPT& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_SCRYPT>::postprocess(std::shared_ptr<Module> module, operation::KDF_SCRYPT& op, const ExecutorBase<component::Key, operation::KDF_SCRYPT>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SCRYPT>::callModule(std::shared_ptr<Module> module, operation::KDF_SCRYPT& op) const {
    return module->OpKDF_SCRYPT(op);
}

/* Specialization for operation::KDF_HKDF */
template<> void ExecutorBase<component::Key, operation::KDF_HKDF>::updateExtraCounters(const uint64_t moduleID, operation::KDF_HKDF& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_HKDF>::postprocess(std::shared_ptr<Module> module, operation::KDF_HKDF& op, const ExecutorBase<component::Key, operation::KDF_HKDF>::ResultPair& result) const {
    (void)module;
    (void)op;
    
    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_HKDF>::callModule(std::shared_ptr<Module> module, operation::KDF_HKDF& op) const {
    return module->OpKDF_HKDF(op);
}

/* Specialization for operation::KDF_PBKDF2 */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF2>::updateExtraCounters(const uint64_t moduleID, operation::KDF_PBKDF2& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_PBKDF2>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF2& op, const ExecutorBase<component::Key, operation::KDF_PBKDF2>::ResultPair& result) const {
    (void)module;
    (void)op;
    
    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF2>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF2& op) const {
    return module->OpKDF_PBKDF2(op);
}

/* Specialization for operation::KDF_TLS1_PRF */
template<> void ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::updateExtraCounters(const uint64_t moduleID, operation::KDF_TLS1_PRF& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::postprocess(std::shared_ptr<Module> module, operation::KDF_TLS1_PRF& op, const ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::ResultPair& result) const {
    (void)module;
    (void)op;
    
    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_TLS1_PRF>::callModule(std::shared_ptr<Module> module, operation::KDF_TLS1_PRF& op) const {
    return module->OpKDF_TLS1_PRF(op);
}

/* Specialization for operation::Sign */
template<> void ExecutorBase<component::Signature, operation::Sign>::updateExtraCounters(const uint64_t moduleID, operation::Sign& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.digestType.Get());
}

template<> void ExecutorBase<component::Signature, operation::Sign>::postprocess(std::shared_ptr<Module> module, operation::Sign& op, const ExecutorBase<component::Signature, operation::Sign>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
    
#if 0
    if ( result.second != std::nullopt ) {
        printf("Result size %zu\n", result.second->GetSize());
        /* Try to verify the signature */

        /* Construct a Verify instance with the Sign instance */
        auto opVerify = operation::Verify(
                /* The Sign instance */
                op,

                /* The signature generated by OpSign */
                *(result.second),

                /* Empty modifier */
                {});

        const auto verificationOK = module->OpVerify(opVerify);
        if ( verificationOK == std::nullopt || verificationOK == false ) {
        }
    }
#endif
}

template<> std::optional<component::Signature> ExecutorBase<component::Signature, operation::Sign>::callModule(std::shared_ptr<Module> module, operation::Sign& op) const {
    return module->OpSign(op);
}

/* Specialization for operation::Verify */
template<> void ExecutorBase<bool, operation::Verify>::updateExtraCounters(const uint64_t moduleID, operation::Verify& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.digestType.Get());
}

template<> void ExecutorBase<bool, operation::Verify>::postprocess(std::shared_ptr<Module> module, operation::Verify& op, const ExecutorBase<bool, operation::Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
    
    /* No postprocessing */
}

template<> std::optional<bool> ExecutorBase<bool, operation::Verify>::callModule(std::shared_ptr<Module> module, operation::Verify& op) const {
    return module->OpVerify(op);
}

template <class ResultType, class OperationType>
ExecutorBase<ResultType, OperationType>::ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules) :
    operationID(operationID),
    modules(modules)
{
}

template <class ResultType, class OperationType>
ExecutorBase<ResultType, OperationType>::~ExecutorBase() {
}

/* Filter away the values in the set that are std::nullopt */
template <class ResultType, class OperationType>
typename ExecutorBase<ResultType, OperationType>::ResultSet ExecutorBase<ResultType, OperationType>::filter(const ResultSet& results) const {
    ResultSet ret;

    for (const auto& result : results) {
        if ( result.second == std::nullopt ) {
            continue;
        }

        ret.push_back(result);
    }

    return ret;
}

template <class ResultType, class OperationType>
void ExecutorBase<ResultType, OperationType>::compare(const ResultSet& results, const uint8_t* data, const size_t size) const {
    if ( results.size() < 2 ) {
        /* Nothing to compare. Don't even bother filtering. */
        return;
    }

    const auto filtered = filter(results);

    if ( filtered.size() < 2 ) {
        /* Nothing to compare */
        return;
    }

    for (size_t i = 1; i < filtered.size(); i++) {
        const std::optional<ResultType>& prev = filtered[i-1].second;
        const std::optional<ResultType>& cur = filtered[i].second;

        const bool equal = *prev == *cur;

        if ( !equal ) {
            /* Reconstruct operation */
            const auto op = getOp(nullptr, data, size);

            printf("Difference detected\n\n");
            printf("Operation:\n%s\n", op.ToString().c_str());
            printf("Module %s result:\n\n%s\n\n", filtered[i-1].first->name.c_str(), util::ToString(*prev).c_str());
            printf("Module %s result:\n\n%s\n\n", filtered[i].first->name.c_str(), util::ToString(*cur).c_str());

            abort();
        }
    }
}

template <class ResultType, class OperationType>
OperationType ExecutorBase<ResultType, OperationType>::getOp(Datasource* parentDs, const uint8_t* data, const size_t size) const {
    Datasource ds(data, size);
    if ( parentDs != nullptr ) {
        auto modifier = parentDs->GetData(0);
        return std::move( OperationType(ds, component::Modifier(modifier.data(), modifier.size())) );
    } else {
        return std::move( OperationType(ds, component::Modifier(nullptr, 0)) );
    }
}

template <class ResultType, class OperationType>
std::shared_ptr<Module> ExecutorBase<ResultType, OperationType>::getModule(Datasource& ds) const {
    const auto moduleID = ds.Get<uint64_t>();

    if ( modules.find(moduleID) == modules.end() ) {
        return nullptr;
    }

    return modules.at(moduleID);
}

template <class ResultType, class OperationType>
void ExecutorBase<ResultType, OperationType>::updateExtraCounters(
        const uint64_t moduleID,
        const uint64_t operation,
        const uint64_t operationDetail0,
        const uint64_t operationDetail1,
        const uint64_t operationDetail2) const {
    extraCounterData.moduleID += moduleID;
    extraCounterData.operation = operation;
    extraCounterData.operationDetail[0] = operationDetail0;
    extraCounterData.operationDetail[2] = operationDetail1;
    extraCounterData.operationDetail[1] = operationDetail2;
}

template <class ResultType, class OperationType>
void ExecutorBase<ResultType, OperationType>::Run(Datasource& parentDs, const uint8_t* data, const size_t size) const {
    typename ExecutorBase<ResultType, OperationType>::ResultSet results;

    std::vector< std::pair<std::shared_ptr<Module>, OperationType> > operations;

    do {
        auto op = getOp(&parentDs, data, size);
        auto module = getModule(parentDs);
        if ( module == nullptr ) {
            continue;
        }

        operations.push_back( {module, op} );
    } while ( parentDs.Get<bool>() == true );

    /*
     * Enable this to test results of min. 2 modules always
    if ( operations.size() < 2 ) {
        return;
    }
    */

    for (size_t i = 0; i < operations.size(); i++) {
        auto& operation = operations[i];

        auto& module = operation.first;
        auto& op = operation.second;

        if ( i > 0 ) {
            auto& prevModule = operations[i-1].first;
            auto& prevOp = operations[i].second;

            if ( prevModule == module && prevOp.modifier == op.modifier ) {
                auto& curModifier = op.modifier.GetVectorPtr();
                if ( curModifier.size() == 0 ) {
                    for (size_t j = 0; j < 512; j++) {
                        curModifier.push_back(1);
                    }
                } else {
                    for (auto& c : curModifier) {
                        c++;
                    }
                }
            }
        }

        results.push_back( {module, std::move(callModule(module, op))} );

        const auto& result = results.back();

        if ( result.second != std::nullopt ) {
            updateExtraCounters(module->ID, op);
        }

        tests::test(op, result.second);

        postprocess(module, op, result);
    }

    compare(results, data, size);
}

/* Explicit template instantiation */
template class ExecutorBase<component::Digest, operation::Digest>; 
template class ExecutorBase<component::MAC, operation::HMAC>; 
template class ExecutorBase<component::MAC, operation::CMAC>; 
template class ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>; 
template class ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>; 
template class ExecutorBase<component::Key, operation::KDF_SCRYPT>; 
template class ExecutorBase<component::Key, operation::KDF_HKDF>; 
template class ExecutorBase<component::Key, operation::KDF_TLS1_PRF>; 
template class ExecutorBase<component::Key, operation::KDF_PBKDF2>; 
template class ExecutorBase<component::Signature, operation::Sign>; 
template class ExecutorBase<bool, operation::Verify>; 

} /* namespace cryptofuzz */
