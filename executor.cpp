#include "executor.h"
#include "tests.h"
#include "mutatorpool.h"
#include "config.h"
#include <cryptofuzz/util.h>
#include <fuzzing/memory.hpp>
#include <algorithm>
#include <set>

uint32_t PRNG(void);

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
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
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
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
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
    /* Only run whitelisted ciphers, if specified */
    if ( options.ciphers != std::nullopt ) {
        if ( std::find(
                    options.ciphers->begin(),
                    options.ciphers->end(),
                    op.cipher.cipherType.Get()) == options.ciphers->end() ) {
            return std::nullopt;
        }
    }
    return module->OpCMAC(op);
}

/* Specialization for operation::SymmetricEncrypt */
template<> void ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::updateExtraCounters(const uint64_t moduleID, operation::SymmetricEncrypt& op) const {
    using fuzzing::datasource::ID;
    updateExtraCounters(moduleID, operationID, op.cleartext.Get().size(), op.cipher.cipherType.Get(), op.cipher.iv.Get().size());
}

template<> void ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::postprocess(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op, const ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::ResultPair& result) const {
    if ( options.noDecrypt == true ) {
        return;
    }

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->ciphertext.GetPtr(), result.second->ciphertext.GetSize());
        if ( result.second->tag != std::nullopt ) {
            fuzzing::memory::memory_test_msan(result.second->tag->GetPtr(), result.second->tag->GetSize());
        }
    }

    if ( op.cleartext.GetSize() > 0 && result.second != std::nullopt && result.second->ciphertext.GetSize() > 0 ) {
        using fuzzing::datasource::ID;

        bool tryDecrypt = true;

        if ( module->ID == CF_MODULE("OpenSSL") ) {
            switch ( op.cipher.cipherType.Get() ) {
                case    ID("Cryptofuzz/Cipher/AES_128_OCB"):
                case    ID("Cryptofuzz/Cipher/AES_256_OCB"):
                    tryDecrypt = false;
                    break;
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
                    if ( op.tagSize == std::nullopt ) {
                        /* OpenSSL fails to decrypt its own CCM and GCM ciphertexts if
                         * a tag is not included
                         */
                        tryDecrypt = false;
                    }
                    break;
            }
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

                    op.aad,

                    /* Empty modifier */
                    {});

            const auto cleartext = module->OpSymmetricDecrypt(opDecrypt);

            if ( cleartext == std::nullopt ) {
                /* Decryption failed, OpSymmetricDecrypt() returned std::nullopt */
                printf("Cannot decrypt ciphertext\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->ciphertext.Get()).c_str());
                printf("Tag: %s\n", result.second->tag ? util::HexDump(result.second->tag->Get()).c_str() : "nullopt");
                abort(
                        {module->name},
                        op.Name(),
                        op.GetAlgorithmString(),
                        "cannot decrypt ciphertext"
                );
            } else if ( cleartext->Get() != op.cleartext.Get() ) {
                /* Decryption ostensibly succeeded, but the cleartext returned by OpSymmetricDecrypt()
                 * does not match to original cleartext */

                printf("Cannot decrypt ciphertext (but decryption ostensibly succeeded)\n\n");
                printf("Operation:\n%s\n", op.ToString().c_str());
                printf("Ciphertext: %s\n", util::HexDump(result.second->ciphertext.Get()).c_str());
                printf("Tag: %s\n", result.second->tag ? util::HexDump(result.second->tag->Get()).c_str() : "nullopt");
                printf("Purported cleartext: %s\n", util::HexDump(cleartext->Get()).c_str());
                abort(
                        {module->name},
                        op.Name(),
                        op.GetAlgorithmString(),
                        "cannot decrypt ciphertext"
                );
            }
        }
    }
}

template<> std::optional<component::Ciphertext> ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::callModule(std::shared_ptr<Module> module, operation::SymmetricEncrypt& op) const {
    /* Only run whitelisted ciphers, if specified */
    if ( options.ciphers != std::nullopt ) {
        if ( std::find(
                    options.ciphers->begin(),
                    options.ciphers->end(),
                    op.cipher.cipherType.Get()) == options.ciphers->end() ) {
            return std::nullopt;
        }
    }
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
    /* Only run whitelisted ciphers, if specified */
    if ( options.ciphers != std::nullopt ) {
        if ( std::find(
                    options.ciphers->begin(),
                    options.ciphers->end(),
                    op.cipher.cipherType.Get()) == options.ciphers->end() ) {
            return std::nullopt;
        }
    }
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
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_HKDF(op);
}

/* Specialization for operation::KDF_PBKDF */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF>::updateExtraCounters(const uint64_t moduleID, operation::KDF_PBKDF& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_PBKDF>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF& op, const ExecutorBase<component::Key, operation::KDF_PBKDF>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF& op) const {
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_PBKDF(op);
}

/* Specialization for operation::KDF_PBKDF1 */
template<> void ExecutorBase<component::Key, operation::KDF_PBKDF1>::updateExtraCounters(const uint64_t moduleID, operation::KDF_PBKDF1& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_PBKDF1>::postprocess(std::shared_ptr<Module> module, operation::KDF_PBKDF1& op, const ExecutorBase<component::Key, operation::KDF_PBKDF1>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_PBKDF1>::callModule(std::shared_ptr<Module> module, operation::KDF_PBKDF1& op) const {
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_PBKDF1(op);
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
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_PBKDF2(op);
}

/* Specialization for operation::KDF_ARGON2 */
template<> void ExecutorBase<component::Key, operation::KDF_ARGON2>::updateExtraCounters(const uint64_t moduleID, operation::KDF_ARGON2& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

/* Specialization for operation::KDF_SSH */
template<> void ExecutorBase<component::Key, operation::KDF_SSH>::updateExtraCounters(const uint64_t moduleID, operation::KDF_SSH& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_ARGON2>::postprocess(std::shared_ptr<Module> module, operation::KDF_ARGON2& op, const ExecutorBase<component::Key, operation::KDF_ARGON2>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_ARGON2>::callModule(std::shared_ptr<Module> module, operation::KDF_ARGON2& op) const {
    return module->OpKDF_ARGON2(op);
}

template<> void ExecutorBase<component::Key, operation::KDF_SSH>::postprocess(std::shared_ptr<Module> module, operation::KDF_SSH& op, const ExecutorBase<component::Key, operation::KDF_SSH>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SSH>::callModule(std::shared_ptr<Module> module, operation::KDF_SSH& op) const {
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_SSH(op);
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
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_TLS1_PRF(op);
}

/* Specialization for operation::KDF_X963 */
template<> void ExecutorBase<component::Key, operation::KDF_X963>::updateExtraCounters(const uint64_t moduleID, operation::KDF_X963& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_X963>::postprocess(std::shared_ptr<Module> module, operation::KDF_X963& op, const ExecutorBase<component::Key, operation::KDF_X963>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_X963>::callModule(std::shared_ptr<Module> module, operation::KDF_X963& op) const {
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_X963(op);
}

/* Specialization for operation::KDF_BCRYPT */
template<> void ExecutorBase<component::Key, operation::KDF_BCRYPT>::updateExtraCounters(const uint64_t moduleID, operation::KDF_BCRYPT& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_BCRYPT>::postprocess(std::shared_ptr<Module> module, operation::KDF_BCRYPT& op, const ExecutorBase<component::Key, operation::KDF_BCRYPT>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_BCRYPT>::callModule(std::shared_ptr<Module> module, operation::KDF_BCRYPT& op) const {
    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }
    return module->OpKDF_BCRYPT(op);
}

/* Specialization for operation::KDF_SP_800_108 */
template<> void ExecutorBase<component::Key, operation::KDF_SP_800_108>::updateExtraCounters(const uint64_t moduleID, operation::KDF_SP_800_108& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Key, operation::KDF_SP_800_108>::postprocess(std::shared_ptr<Module> module, operation::KDF_SP_800_108& op, const ExecutorBase<component::Key, operation::KDF_SP_800_108>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt ) {
        fuzzing::memory::memory_test_msan(result.second->GetPtr(), result.second->GetSize());
    }
}

template<> std::optional<component::Key> ExecutorBase<component::Key, operation::KDF_SP_800_108>::callModule(std::shared_ptr<Module> module, operation::KDF_SP_800_108& op) const {
    if ( op.mech.mode == true ) {
        /* Only run whitelisted digests, if specified */
        if ( options.digests != std::nullopt ) {
            if ( std::find(
                        options.digests->begin(),
                        options.digests->end(),
                        op.mech.type.Get()) == options.digests->end() ) {
                return std::nullopt;
            }
        }
    }
    return module->OpKDF_SP_800_108(op);
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

/* Specialization for operation::ECC_PrivateToPublic */
template<> void ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::updateExtraCounters(const uint64_t moduleID, operation::ECC_PrivateToPublic& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::postprocess(std::shared_ptr<Module> module, operation::ECC_PrivateToPublic& op, const ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto privkey = op.priv.ToTrimmedString();
        const auto pub_x = result.second->first.ToTrimmedString();
        const auto pub_y = result.second->second.ToTrimmedString();

        Pool_CurvePrivkey.Set({ curveID, privkey });
        Pool_CurveKeypair.Set({ curveID, privkey, pub_x, pub_y });

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
    }
}

template<> std::optional<component::ECC_PublicKey> ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>::callModule(std::shared_ptr<Module> module, operation::ECC_PrivateToPublic& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECC_PrivateToPublic(op);
}

/* Specialization for operation::ECC_ValidatePubkey */
template<> void ExecutorBase<bool, operation::ECC_ValidatePubkey>::updateExtraCounters(const uint64_t moduleID, operation::ECC_ValidatePubkey& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<bool, operation::ECC_ValidatePubkey>::postprocess(std::shared_ptr<Module> module, operation::ECC_ValidatePubkey& op, const ExecutorBase<bool, operation::ECC_ValidatePubkey>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECC_ValidatePubkey>::callModule(std::shared_ptr<Module> module, operation::ECC_ValidatePubkey& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }

    return module->OpECC_ValidatePubkey(op);
}

/* Specialization for operation::ECC_GenerateKeyPair */

/* Do not compare DH_GenerateKeyPair results, because the result can be produced indeterministically */
template <>
void ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::compare(const std::vector< std::pair<std::shared_ptr<Module>, operation::DH_GenerateKeyPair> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const {
    (void)operations;
    (void)results;
    (void)data;
    (void)size;
}

template<> void ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::updateExtraCounters(const uint64_t moduleID, operation::ECC_GenerateKeyPair& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::postprocess(std::shared_ptr<Module> module, operation::ECC_GenerateKeyPair& op, const ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto privkey = result.second->priv.ToTrimmedString();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();

        Pool_CurvePrivkey.Set({ curveID, privkey });
        Pool_CurveKeypair.Set({ curveID, privkey, pub_x, pub_y });
    }
}

template<> std::optional<component::ECC_KeyPair> ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::callModule(std::shared_ptr<Module> module, operation::ECC_GenerateKeyPair& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }
    return module->OpECC_GenerateKeyPair(op);
}

/* Specialization for operation::ECDSA_Sign */
template<> void ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::updateExtraCounters(const uint64_t moduleID, operation::ECDSA_Sign& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::postprocess(std::shared_ptr<Module> module, operation::ECDSA_Sign& op, const ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::ResultPair& result) const {
    (void)module;

    if ( result.second != std::nullopt  ) {
        const auto curveID = op.curveType.Get();
        const auto cleartext = op.cleartext.ToHex();
        const auto pub_x = result.second->pub.first.ToTrimmedString();
        const auto pub_y = result.second->pub.second.ToTrimmedString();
        const auto sig_r = result.second->signature.first.ToTrimmedString();
        const auto sig_s = result.second->signature.second.ToTrimmedString();

        Pool_CurveECDSASignature.Set({ curveID, cleartext, pub_x, pub_y, sig_r, sig_s});

        if ( pub_x.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_x); }
        if ( pub_y.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(pub_y); }
        if ( sig_r.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_r); }
        if ( sig_s.size() <= config::kMaxBignumSize ) { Pool_Bignum.Set(sig_s); }
    }
}

template<> std::optional<component::ECDSA_Signature> ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::callModule(std::shared_ptr<Module> module, operation::ECDSA_Sign& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }

    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt && op.digestType.Get() != 0 ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }

    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpECDSA_Sign(op);
}

/* Specialization for operation::ECDSA_Verify */
template<> void ExecutorBase<bool, operation::ECDSA_Verify>::updateExtraCounters(const uint64_t moduleID, operation::ECDSA_Verify& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<bool, operation::ECDSA_Verify>::postprocess(std::shared_ptr<Module> module, operation::ECDSA_Verify& op, const ExecutorBase<bool, operation::ECDSA_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::ECDSA_Verify>::callModule(std::shared_ptr<Module> module, operation::ECDSA_Verify& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }

    /* Only run whitelisted digests, if specified */
    if ( options.digests != std::nullopt && op.digestType.Get() != 0 ) {
        if ( std::find(
                    options.digests->begin(),
                    options.digests->end(),
                    op.digestType.Get()) == options.digests->end() ) {
            return std::nullopt;
        }
    }

    /* Intentionally do not constrain the size of the public key or
     * signature (like we do for BignumCalc).
     *
     * If any large public key or signature causes a time-out (or
     * worse), this is something that needs attention;
     * because verifiers sometimes process untrusted public keys,
     * signatures or both, they should be resistant to bugs
     * arising from large inputs.
     */

    return module->OpECDSA_Verify(op);
}

/* Specialization for operation::ECDH_Derive */
template<> void ExecutorBase<component::Secret, operation::ECDH_Derive>::updateExtraCounters(const uint64_t moduleID, operation::ECDH_Derive& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Secret, operation::ECDH_Derive>::postprocess(std::shared_ptr<Module> module, operation::ECDH_Derive& op, const ExecutorBase<component::Secret, operation::ECDH_Derive>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Secret> ExecutorBase<component::Secret, operation::ECDH_Derive>::callModule(std::shared_ptr<Module> module, operation::ECDH_Derive& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }
    return module->OpECDH_Derive(op);
}

/* Specialization for operation::ECIES_Encrypt */
template<> void ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::updateExtraCounters(const uint64_t moduleID, operation::ECIES_Encrypt& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::postprocess(std::shared_ptr<Module> module, operation::ECIES_Encrypt& op, const ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Ciphertext> ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>::callModule(std::shared_ptr<Module> module, operation::ECIES_Encrypt& op) const {
    /* Only run whitelisted curves, if specified */
    if ( options.curves != std::nullopt ) {
        if ( std::find(
                    options.curves->begin(),
                    options.curves->end(),
                    op.curveType.Get()) == options.curves->end() ) {
            return std::nullopt;
        }
    }
    return module->OpECIES_Encrypt(op);
}

/* Specialization for operation::DH_Derive */
template<> void ExecutorBase<component::Bignum, operation::DH_Derive>::updateExtraCounters(const uint64_t moduleID, operation::DH_Derive& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Bignum, operation::DH_Derive>::postprocess(std::shared_ptr<Module> module, operation::DH_Derive& op, const ExecutorBase<component::Bignum, operation::DH_Derive>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::Bignum> ExecutorBase<component::Bignum, operation::DH_Derive>::callModule(std::shared_ptr<Module> module, operation::DH_Derive& op) const {
    if ( op.prime.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.base.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.pub.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.priv.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpDH_Derive(op);
}

/* Specialization for operation::DH_GenerateKeyPair */
template<> void ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::updateExtraCounters(const uint64_t moduleID, operation::DH_GenerateKeyPair& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::postprocess(std::shared_ptr<Module> module, operation::DH_GenerateKeyPair& op, const ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::ResultPair& result) const {
    (void)result;
    (void)op;
    (void)module;

    if ( result.second != std::nullopt && (PRNG() % 4) == 0 ) {
        const auto priv = result.second->first.ToTrimmedString();
        const auto pub = result.second->second.ToTrimmedString();

        Pool_DH_PrivateKey.Set(priv);
        Pool_DH_PublicKey.Set(pub);
    }
}

template<> std::optional<component::DH_KeyPair> ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>::callModule(std::shared_ptr<Module> module, operation::DH_GenerateKeyPair& op) const {
    if ( op.prime.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.base.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    return module->OpDH_GenerateKeyPair(op);
}

/* Specialization for operation::BignumCalc */
template<> void ExecutorBase<component::Bignum, operation::BignumCalc>::updateExtraCounters(const uint64_t moduleID, operation::BignumCalc& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::Bignum, operation::BignumCalc>::postprocess(std::shared_ptr<Module> module, operation::BignumCalc& op, const ExecutorBase<component::Bignum, operation::BignumCalc>::ResultPair& result) const {
    (void)module;
    (void)op;

    if ( result.second != std::nullopt  ) {
        const auto bignum = result.second->ToTrimmedString();

        if ( bignum.size() <= config::kMaxBignumSize ) {
            Pool_Bignum.Set(bignum);
        }
    }
}

template<> std::optional<component::Bignum> ExecutorBase<component::Bignum, operation::BignumCalc>::callModule(std::shared_ptr<Module> module, operation::BignumCalc& op) const {
    /* Only run whitelisted calcops, if specified */
    if ( options.calcOps != std::nullopt ) {
        if ( std::find(
                    options.calcOps->begin(),
                    options.calcOps->end(),
                    op.calcOp.Get()) == options.calcOps->end() ) {
            return std::nullopt;
        }
    }

    /* Prevent timeouts */
    if ( op.bn0.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn1.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn2.GetSize() > config::kMaxBignumSize ) return std::nullopt;
    if ( op.bn3.GetSize() > config::kMaxBignumSize ) return std::nullopt;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("SetBit(A,B)"):
            /* Don't allow setting very high bit positions (risk of memory exhaustion) */
            if ( op.bn1.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("Exp(A,B)"):
            if ( op.bn0.GetSize() > 5 || op.bn1.GetSize() > 2 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("ModLShift(A,B,C)"):
            if ( op.bn1.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
        case    CF_CALCOP("Exp2(A)"):
            if ( op.bn0.GetSize() > 4 ) {
                return std::nullopt;
            }
            break;
    }

    return module->OpBignumCalc(op);
}

/* Specialization for operation::BLS_PrivateToPublic */
template<> void ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::updateExtraCounters(const uint64_t moduleID, operation::BLS_PrivateToPublic& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::postprocess(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic& op, const ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::BLS_PublicKey> ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>::callModule(std::shared_ptr<Module> module, operation::BLS_PrivateToPublic& op) const {
    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpBLS_PrivateToPublic(op);
}

/* Specialization for operation::BLS_Sign */
template<> void ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::updateExtraCounters(const uint64_t moduleID, operation::BLS_Sign& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::postprocess(std::shared_ptr<Module> module, operation::BLS_Sign& op, const ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::BLS_Signature> ExecutorBase<component::BLS_Signature, operation::BLS_Sign>::callModule(std::shared_ptr<Module> module, operation::BLS_Sign& op) const {
    const size_t size = op.priv.ToTrimmedString().size();

    if ( size == 0 || size > 4096 ) {
        return std::nullopt;
    }

    return module->OpBLS_Sign(op);
}

/* Specialization for operation::BLS_Verify */
template<> void ExecutorBase<bool, operation::BLS_Verify>::updateExtraCounters(const uint64_t moduleID, operation::BLS_Verify& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<bool, operation::BLS_Verify>::postprocess(std::shared_ptr<Module> module, operation::BLS_Verify& op, const ExecutorBase<bool, operation::BLS_Verify>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_Verify>::callModule(std::shared_ptr<Module> module, operation::BLS_Verify& op) const {
    const std::vector<size_t> sizes = {
        op.pub.first.ToTrimmedString().size(),
        op.pub.second.ToTrimmedString().size(),
        op.signature.first.ToTrimmedString().size(),
        op.signature.second.ToTrimmedString().size(),
    };

    for (const auto& size : sizes) {
        if ( size == 0 || size > 4096 ) {
            return std::nullopt;
        }
    }

    return module->OpBLS_Verify(op);
}

/* Specialization for operation::BLS_Pairing */
template<> void ExecutorBase<bool, operation::BLS_Pairing>::updateExtraCounters(const uint64_t moduleID, operation::BLS_Pairing& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<bool, operation::BLS_Pairing>::postprocess(std::shared_ptr<Module> module, operation::BLS_Pairing& op, const ExecutorBase<bool, operation::BLS_Pairing>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<bool> ExecutorBase<bool, operation::BLS_Pairing>::callModule(std::shared_ptr<Module> module, operation::BLS_Pairing& op) const {
    return module->OpBLS_Pairing(op);
}

/* Specialization for operation::BLS_HashToG1 */
template<> void ExecutorBase<component::G1, operation::BLS_HashToG1>::updateExtraCounters(const uint64_t moduleID, operation::BLS_HashToG1& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::G1, operation::BLS_HashToG1>::postprocess(std::shared_ptr<Module> module, operation::BLS_HashToG1& op, const ExecutorBase<component::G1, operation::BLS_HashToG1>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::G1> ExecutorBase<component::G1, operation::BLS_HashToG1>::callModule(std::shared_ptr<Module> module, operation::BLS_HashToG1& op) const {
    return module->OpBLS_HashToG1(op);
}

/* Specialization for operation::BLS_HashToG2 */
template<> void ExecutorBase<component::G2, operation::BLS_HashToG2>::updateExtraCounters(const uint64_t moduleID, operation::BLS_HashToG2& op) const {
    (void)moduleID;
    (void)op;

    /* TODO */
}

template<> void ExecutorBase<component::G2, operation::BLS_HashToG2>::postprocess(std::shared_ptr<Module> module, operation::BLS_HashToG2& op, const ExecutorBase<component::G2, operation::BLS_HashToG2>::ResultPair& result) const {
    (void)module;
    (void)op;
    (void)result;
}

template<> std::optional<component::G2> ExecutorBase<component::G2, operation::BLS_HashToG2>::callModule(std::shared_ptr<Module> module, operation::BLS_HashToG2& op) const {
    return module->OpBLS_HashToG2(op);
}

template <class ResultType, class OperationType>
ExecutorBase<ResultType, OperationType>::ExecutorBase(const uint64_t operationID, const std::map<uint64_t, std::shared_ptr<Module> >& modules, const Options& options) :
    operationID(operationID),
    modules(modules),
    options(options)
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

/* Do not compare ECC_GenerateKeyPair results, because the result can be produced indeterministically */
template <>
void ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>::compare(const std::vector< std::pair<std::shared_ptr<Module>, operation::ECC_GenerateKeyPair> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const {
    (void)operations;
    (void)results;
    (void)data;
    (void)size;
}

template <class ResultType, class OperationType>
bool ExecutorBase<ResultType, OperationType>::dontCompare(const OperationType& operation) const {
    (void)operation;

    return false;
}

template <>
bool ExecutorBase<component::Bignum, operation::BignumCalc>::dontCompare(const operation::BignumCalc& operation) const {
    if ( operation.calcOp.Get() == CF_CALCOP("Rand()") ) { return true; }

    return false;
}

template <>
bool ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>::dontCompare(const operation::ECDSA_Sign& operation) const {
    if (
            operation.curveType.Get() != CF_ECC_CURVE("ed25519") &&
            operation.curveType.Get() != CF_ECC_CURVE("ed448") ) {
        if ( operation.UseRandomNonce() ) {
            /* Don't compare ECDSA signatures comptued from a randomly generated nonce */
            return true;
        }
    }

    return false;
}

/* OpenSSL DES_EDE3_WRAP randomizes the IV, result is different each time */
template <>
bool ExecutorBase<component::Ciphertext, operation::SymmetricEncrypt>::dontCompare(const operation::SymmetricEncrypt& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) { return true; }

    return false;
}

template <>
bool ExecutorBase<component::Cleartext, operation::SymmetricDecrypt>::dontCompare(const operation::SymmetricDecrypt& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

template <>
bool ExecutorBase<component::MAC, operation::CMAC>::dontCompare(const operation::CMAC& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

template <>
bool ExecutorBase<component::MAC, operation::HMAC>::dontCompare(const operation::HMAC& operation) const {
    if ( operation.cipher.cipherType.Get() == CF_CIPHER("DES_EDE3_WRAP") ) return true;

    return false;
}

template <class ResultType, class OperationType>
void ExecutorBase<ResultType, OperationType>::compare(const std::vector< std::pair<std::shared_ptr<Module>, OperationType> >& operations, const ResultSet& results, const uint8_t* data, const size_t size) const {
    if ( results.size() < 2 ) {
        /* Nothing to compare. Don't even bother filtering. */
        return;
    }

    const auto filtered = filter(results);

    if ( filtered.size() < 2 ) {
        /* Nothing to compare */
        return;
    }

    if ( dontCompare(operations[0].second) == true ) {
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

            abort(
                    {filtered[i-1].first->name.c_str(), filtered[i].first->name.c_str()},
                    op.Name(),
                    op.GetAlgorithmString(),
                    "difference"
            );
        }
    }
}

template <class ResultType, class OperationType>
void ExecutorBase<ResultType, OperationType>::abort(std::vector<std::string> moduleNames, const std::string operation, const std::string algorithm, const std::string reason) const {
    std::sort(moduleNames.begin(), moduleNames.end());

    printf("Assertion failure: ");
    for (const auto& moduleName : moduleNames) {
        printf("%s-", moduleName.c_str());
    }
    printf("%s-%s-%s\n", operation.c_str(), algorithm.c_str(), reason.c_str());
    fflush(stdout);

    ::abort();
}

template <class ResultType, class OperationType>
OperationType ExecutorBase<ResultType, OperationType>::getOpPostprocess(Datasource* parentDs, OperationType op) const {
    (void)parentDs;
    return std::move(op);
}

template <>
operation::ECDH_Derive ExecutorBase<component::Secret, operation::ECDH_Derive>::getOpPostprocess(Datasource* parentDs, operation::ECDH_Derive op) const {
    /* Decide whether to return the original operation, or construct a new one */
    if ( parentDs->Get<bool>() == true) {
        std::shared_ptr<Module> module = nullptr;
        std::optional<component::ECC_PublicKey> pub1, pub2;
        std::optional<component::ECC_KeyPair> keypair1, keypair2;

        /* Pick random module */
        CF_CHECK_NE(module = getModule(*parentDs), nullptr);

        {
            /* Construct two PrivateToPublic operations */
            auto modifier1 = parentDs->GetData(0);
            operation::ECC_PrivateToPublic op1(*parentDs, component::Modifier(modifier1.data(), modifier1.size()));
            auto modifier2 = parentDs->GetData(0);
            operation::ECC_PrivateToPublic op2(*parentDs, component::Modifier(modifier2.data(), modifier2.size()));

            CF_CHECK_EQ(op1.curveType == op2.curveType, true);

            /* Generate two public keys, using OpECC_PrivateToPublic */
            CF_CHECK_NE(pub1 = module->OpECC_PrivateToPublic(op1), std::nullopt);
            CF_CHECK_NE(pub2 = module->OpECC_PrivateToPublic(op2), std::nullopt);

            /* Construct a new ECDH_Derive operation from these two public keys */
            return operation::ECDH_Derive(op.modifier, op1.curveType, *pub1, *pub2);
        }
    }

end:
    /* Return the original operaton unmodified */
    return op;
}

template <class ResultType, class OperationType>
OperationType ExecutorBase<ResultType, OperationType>::getOp(Datasource* parentDs, const uint8_t* data, const size_t size) const {
    Datasource ds(data, size);
    if ( parentDs != nullptr ) {
        auto modifier = parentDs->GetData(0);
        return getOpPostprocess(parentDs, std::move( OperationType(ds, component::Modifier(modifier.data(), modifier.size())) ) );
    } else {
        return std::move( OperationType(ds, component::Modifier(nullptr, 0)) );
    }
}

template <class ResultType, class OperationType>
std::shared_ptr<Module> ExecutorBase<ResultType, OperationType>::getModule(Datasource& ds) const {
    auto moduleID = ds.Get<uint64_t>();

    /* Override the extracted module ID with the preferred one, if specified */
    if ( options.forceModule != std::nullopt ) {
        moduleID = *options.forceModule;
    }

    /* Skip if this is a disabled module */
    if ( options.disableModules != std::nullopt ) {
        if ( std::find(
                    options.disableModules->begin(),
                    options.disableModules->end(),
                    moduleID) != options.disableModules->end() ) {
            return nullptr;
        }
    }

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

        /* Limit number of operations per run to prevent time-outs */
        if ( operations.size() == OperationType::MaxOperations() ) {
            break;
        }
    } while ( parentDs.Get<bool>() == true );

    if ( operations.empty() == true ) {
        return;
    }

    /* Enable this to run every operation on every loaded module */
#if 1
    {
        std::set<uint64_t> moduleIDs;
        for (const auto& m : modules ) {
            const auto moduleID = m.first;

            /* Skip if this is a disabled module */
            if ( options.disableModules != std::nullopt ) {
                if ( std::find(
                            options.disableModules->begin(),
                            options.disableModules->end(),
                            moduleID) != options.disableModules->end() ) {
                    continue;
                }
            }
            moduleIDs.insert(moduleID);
        }

        std::set<uint64_t> operationModuleIDs;
        for (const auto& op : operations) {
            operationModuleIDs.insert(op.first->ID);
        }

        std::vector<uint64_t> addModuleIDs(moduleIDs.size());
        auto it = std::set_difference(moduleIDs.begin(), moduleIDs.end(), operationModuleIDs.begin(), operationModuleIDs.end(), addModuleIDs.begin());
        addModuleIDs.resize(it - addModuleIDs.begin());

        for (const auto& id : addModuleIDs) {
            operations.push_back({ modules.at(id), operations[0].second});
        }
    }
#endif

    if ( operations.size() < options.minModules ) {
        return;
    }

    if ( options.debug == true && !operations.empty() ) {
        printf("Running:\n%s\n", operations[0].second.ToString().c_str());
    }
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

            if ( options.jsonDumpFP != std::nullopt ) {
                nlohmann::json j;
                j["operation"] = op.ToJSON();
                j["result"] = util::ToJSON(*result.second);
                fprintf(*options.jsonDumpFP, "%s\n", j.dump().c_str());
            }
        }

        if ( options.debug == true ) {
            printf("Module %s result:\n\n%s\n\n",
                    result.first->name.c_str(),
                    result.second == std::nullopt ?
                        "(empty)" :
                        util::ToString(*result.second).c_str());
        }

        if ( options.disableTests == false ) {
            tests::test(op, result.second);
        }

        postprocess(module, op, result);
    }

    if ( options.noCompare == false ) {
        compare(operations, results, data, size);
    }
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
template class ExecutorBase<component::Key, operation::KDF_PBKDF>;
template class ExecutorBase<component::Key, operation::KDF_PBKDF1>;
template class ExecutorBase<component::Key, operation::KDF_PBKDF2>;
template class ExecutorBase<component::Key, operation::KDF_ARGON2>;
template class ExecutorBase<component::Key, operation::KDF_SSH>;
template class ExecutorBase<component::Key, operation::KDF_X963>;
template class ExecutorBase<component::Key, operation::KDF_BCRYPT>;
template class ExecutorBase<component::Key, operation::KDF_SP_800_108>;
template class ExecutorBase<component::Signature, operation::Sign>;
template class ExecutorBase<bool, operation::Verify>;
template class ExecutorBase<component::ECC_PublicKey, operation::ECC_PrivateToPublic>;
template class ExecutorBase<bool, operation::ECC_ValidatePubkey>;
template class ExecutorBase<component::ECC_KeyPair, operation::ECC_GenerateKeyPair>;
template class ExecutorBase<component::ECDSA_Signature, operation::ECDSA_Sign>;
template class ExecutorBase<bool, operation::ECDSA_Verify>;
template class ExecutorBase<component::Secret, operation::ECDH_Derive>;
template class ExecutorBase<component::Ciphertext, operation::ECIES_Encrypt>;
template class ExecutorBase<component::DH_KeyPair, operation::DH_GenerateKeyPair>;
template class ExecutorBase<component::Bignum, operation::DH_Derive>;
template class ExecutorBase<component::Bignum, operation::BignumCalc>;
template class ExecutorBase<component::BLS_PublicKey, operation::BLS_PrivateToPublic>;
template class ExecutorBase<component::BLS_Signature, operation::BLS_Sign>;
template class ExecutorBase<bool, operation::BLS_Verify>;
template class ExecutorBase<bool, operation::BLS_Pairing>;
template class ExecutorBase<component::G1, operation::BLS_HashToG1>;
template class ExecutorBase<component::G2, operation::BLS_HashToG2>;

} /* namespace cryptofuzz */
