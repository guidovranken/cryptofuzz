#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/cipher_mode.h>
#include <botan/pbkdf.h>
#include <botan/pwdhash.h>

namespace cryptofuzz {
namespace module {

Botan::Botan(void) :
    Module("Botan") {
    if ( setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1) != 0 ) {
        abort();
    }
}

namespace Botan_detail {
    const std::string parenthesize(const std::string parent, const std::string child) {
        static const std::string pOpen("(");
        static const std::string pClose(")");

        return parent + pOpen + child + pClose;
    }

    std::optional<std::string> DigestIDToString(const uint64_t digestType) {
        static const std::map<uint64_t, std::string> LUT = {
            { CF_DIGEST("ADLER32"), "Adler32" },
            { CF_DIGEST("BLAKE2B160"), "Blake2b(160)" },
            { CF_DIGEST("BLAKE2B256"), "Blake2b(256)" },
            { CF_DIGEST("BLAKE2B384"), "Blake2b(384)" },
            { CF_DIGEST("BLAKE2B512"), "Blake2b(512)" },
            { CF_DIGEST("CRC32-RFC2440"), "CRC24" },
            { CF_DIGEST("CRC32"), "CRC32" },
            { CF_DIGEST("GOST-R-34.11-94"), "GOST-R-34.11-94" },
            { CF_DIGEST("MD4"), "MD4" },
            { CF_DIGEST("MD5"), "MD5" },
            { CF_DIGEST("RIPEMD160"), "RIPEMD-160" },
            { CF_DIGEST("SHA1"), "SHA1" },
            { CF_DIGEST("SHA224"), "SHA-224" },
            { CF_DIGEST("SHA256"), "SHA-256" },
            { CF_DIGEST("SHA384"), "SHA-384" },
            { CF_DIGEST("SHA512"), "SHA-512" },
            { CF_DIGEST("SHA3-224"), "SHA-3(224)" },
            { CF_DIGEST("SHA3-256"), "SHA-3(256)" },
            { CF_DIGEST("SHA3-384"), "SHA-3(384)" },
            { CF_DIGEST("SHA3-512"), "SHA-3(512)" },
            { CF_DIGEST("SKEIN_512"), "Skein-512" },
            { CF_DIGEST("SM3"), "SM3" },
            { CF_DIGEST("STREEBOG-256"), "Streebog-256" },
            { CF_DIGEST("STREEBOG-512"), "Streebog-512" },
            { CF_DIGEST("TIGER"), "Tiger" },
            { CF_DIGEST("WHIRLPOOL"), "Whirlpool" },
            { CF_DIGEST("SHA512-256"), "SHA-512-256" },
            { CF_DIGEST("SHAKE128"), "SHAKE-128(128)" },
            { CF_DIGEST("SHAKE256"), "SHAKE-256(256)" },
            { CF_DIGEST("KECCAK_224"), "Keccak-1600(224)" },
            { CF_DIGEST("KECCAK_256"), "Keccak-1600(256)" },
            { CF_DIGEST("KECCAK_384"), "Keccak-1600(384)" },
            { CF_DIGEST("KECCAK_512"), "Keccak-1600(512)" },
        };

        std::optional<std::string> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(digestType), LUT.end());
        ret = LUT.at(digestType);
end:
        return ret;
    }

} /* namespace Botan_detail */

std::optional<component::Digest> Botan::OpDigest(operation::Digest& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;
    std::unique_ptr<::Botan::HashFunction> hash = nullptr;
    util::Multipart parts;
    size_t numClears = 0;

    /* Initialize */
    {
        std::optional<std::string> algoString;
        CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);
        CF_CHECK_NE(hash = ::Botan::HashFunction::create(*algoString), nullptr);

        parts = util::ToParts(ds, op.cleartext);
    }

again:
    /* Process */
    for (const auto& part : parts) {
        hash->update(part.first, part.second);
        bool clear = false;

        if ( numClears < 3 ) {
            try {
                clear = ds.Get<bool>();
            } catch ( ... ) {
            }
        }

        if ( clear == true ) {
            hash->clear();
            numClears++;
            goto again;
        }
    }

    /* Finalize */
    {
        const auto res = hash->final();
        ret = component::Digest(res.data(), res.size());
    }

end:

    return ret;
}

std::optional<component::MAC> Botan::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;
    std::unique_ptr<::Botan::MessageAuthenticationCode> hmac = nullptr;
    util::Multipart parts;

    try {
        /* Initialize */
        {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);
            std::string algoStringCopy = *algoString;
            if ( algoStringCopy == "SHAKE-128(128)" ) {
                algoStringCopy = "SHAKE-128(256)";
            } else if ( algoStringCopy == "SHAKE-256(256)" ) {
                algoStringCopy = "SHAKE-256(512)";
            }

            const std::string hmacString = Botan_detail::parenthesize("HMAC", algoStringCopy);
            CF_CHECK_NE(hmac = ::Botan::MessageAuthenticationCode::create(hmacString), nullptr);

            try {
                hmac->set_key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } catch ( ... ) {
                goto end;
            }

            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            hmac->update(part.first, part.second);
        }

        /* Finalize */
        {
            const auto res = hmac->final();
            ret = component::MAC(res.data(), res.size());
        }

    } catch ( ... ) { }
end:

    return ret;
}

namespace Botan_detail {

    std::optional<std::string> CipherIDToString(const uint64_t digestType) {
        static const std::map<uint64_t, std::string> LUT = {
            { CF_CIPHER("AES_128_CBC"), "AES-128/CBC" },
            { CF_CIPHER("AES_128_CTR"), "AES-128/CTR" },
            { CF_CIPHER("AES_128_OCB"), "AES-128/OCB" },
            { CF_CIPHER("AES_128_XTS"), "AES-128/XTS" },
            { CF_CIPHER("AES_192_CBC"), "AES-192/CBC" },
            { CF_CIPHER("AES_192_CTR"), "AES-192/CTR" },
            { CF_CIPHER("AES_256_CBC"), "AES-256/CBC" },
            { CF_CIPHER("AES_256_CTR"), "AES-256/CTR" },
            { CF_CIPHER("AES_256_OCB"), "AES-256/OCB" },
            { CF_CIPHER("AES_256_XTS"), "AES-256/XTS" },
            { CF_CIPHER("ARIA_128_CBC"), "ARIA-128/CBC" },
            { CF_CIPHER("ARIA_128_CTR"), "ARIA-128/CTR" },
            { CF_CIPHER("ARIA_192_CBC"), "ARIA-192/CBC" },
            { CF_CIPHER("ARIA_192_CTR"), "ARIA-192/CTR" },
            { CF_CIPHER("ARIA_256_CBC"), "ARIA-256/CBC" },
            { CF_CIPHER("ARIA_256_CTR"), "ARIA-256/CTR" },
            { CF_CIPHER("BF_CBC"), "Blowfish/CBC" },
            { CF_CIPHER("CAMELLIA_128_CBC"), "Camellia-128/CBC" },
            { CF_CIPHER("CAMELLIA_128_ECB"), "Camellia-128/ECB" },
            { CF_CIPHER("CAMELLIA_192_CBC"), "Camellia-192/CBC" },
            { CF_CIPHER("CAMELLIA_192_ECB"), "Camellia-192/ECB" },
            { CF_CIPHER("CAMELLIA_256_CBC"), "Camellia-256/CBC" },
            { CF_CIPHER("CAMELLIA_256_ECB"), "Camellia-256/ECB" },
            { CF_CIPHER("CAST5_CBC"), "CAST5/CBC" },
            { CF_CIPHER("CAST5_ECB"), "CAST5/ECB" },
            { CF_CIPHER("CHACHA20"), "ChaCha(20)" },
            { CF_CIPHER("DESX_B_CBC"), "DESX/CBC" },
            { CF_CIPHER("DES_CBC"), "DES/CBC" },
            { CF_CIPHER("DES_ECB"), "DES/ECB" },
            { CF_CIPHER("DES_EDE3_CBC"), "DES-EDE/CCB" },
            { CF_CIPHER("DES_EDE3_ECB"), "DES-EDE/ECB" },
            { CF_CIPHER("IDEA_CBC"), "IDEA/CBC" },
            { CF_CIPHER("IDEA_ECB"), "IDEA/ECB" },
            { CF_CIPHER("SEED_CBC"), "SEED/CBC" },
            { CF_CIPHER("SEED_ECB"), "SEED/ECB" },
            { CF_CIPHER("SEED_OFB"), "SEED/OFB" },
            { CF_CIPHER("SM4_CBC"), "SM4/CBC" },
            { CF_CIPHER("SM4_CTR"), "SM4/CTR" },
            { CF_CIPHER("SM4_ECB"), "SM4/ECB" },
            { CF_CIPHER("SM4_OFB"), "SM4/OFB" },
            //{ CF_CIPHER("GOST-28147-89"), "GOST-28147-89/CBC" },
        };

        std::optional<std::string> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(digestType), LUT.end());
        ret = LUT.at(digestType);
end:
        return ret;
    }

    template <class OperationType>
    const uint8_t* GetInPtr(const OperationType& op);

    template <>
    const uint8_t* GetInPtr(const operation::SymmetricEncrypt& op) {
        return op.cleartext.GetPtr();
    }

    template <>
    const uint8_t* GetInPtr(const operation::SymmetricDecrypt& op) {
        return op.ciphertext.GetPtr();
    }

    template <class OperationType>
    size_t GetInSize(const OperationType& op);

    template <>
    size_t GetInSize(const operation::SymmetricEncrypt& op) {
        return op.cleartext.GetSize();
    }

    template <>
    size_t GetInSize(const operation::SymmetricDecrypt& op) {
        return op.ciphertext.GetSize();
    }

    template <class OperationType>
    ::Botan::secure_vector<uint8_t> GetInData(const OperationType& op) {
        return ::Botan::secure_vector<uint8_t>(GetInPtr(op), GetInPtr(op) + GetInSize(op));
    }

    template <class OperationType>
    ::Botan::Cipher_Dir GetCryptType(void);

    template <>
    ::Botan::Cipher_Dir GetCryptType<operation::SymmetricEncrypt>(void) {
        return ::Botan::ENCRYPTION;
    }

    template <>
    ::Botan::Cipher_Dir GetCryptType<operation::SymmetricDecrypt>(void) {
        return ::Botan::DECRYPTION;
    }

    template <class ReturnType, class OperationType>
        std::optional<ReturnType> Crypt(OperationType& op) {
            std::optional<ReturnType> ret = std::nullopt;
            Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

            std::unique_ptr<::Botan::Cipher_Mode> crypt = nullptr;
            const ::Botan::SymmetricKey key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            const ::Botan::InitializationVector iv(op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
            ::Botan::secure_vector<uint8_t> in = GetInData(op);
            std::vector<uint8_t> out;
            bool useOneShot = true;
            util::Multipart parts;

            try {
                /* Initialize */
                {
                    std::optional<std::string> algoString;
                    CF_CHECK_NE(algoString = Botan_detail::CipherIDToString(op.cipher.cipherType.Get()), std::nullopt);
                    CF_CHECK_NE(crypt = ::Botan::Cipher_Mode::create(*algoString, GetCryptType<OperationType>()), nullptr);
                    crypt->set_key(key);
                    crypt->start(iv.bits_of());
                    if ( crypt->update_granularity() == 1 ) {
                        try {
                            useOneShot = ds.Get<bool>();
                        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                    }
                    if ( useOneShot == false ) {
                        parts = util::ToParts(ds, GetInPtr(op), GetInSize(op));
                    }
                }

                /* Process */
                {
                    /* TODO aad/tag */

                    if ( useOneShot == true ) {
                        crypt->finish(in);
                    } else {
                        for (const auto& part : parts) {
                            std::vector<uint8_t> tmp(part.first, part.first + part.second);
                            crypt->process(tmp.data(), tmp.size());
                            out.insert(out.end(), tmp.begin(), tmp.end());
                        }
                    }
                }

                /* Finalize */
                {
                    /* TODO take max output size in consideration */

                    if ( useOneShot == true ) {
                        ret = ReturnType(Buffer(in.data(), in.size()));
                    } else {
                        ret = ReturnType(Buffer(out.data(), out.size()));
                    }
                }
            } catch ( ... ) { }
end:

            return ret;
        }

} /* namespace Botan_detail */

std::optional<component::Ciphertext> Botan::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    return Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt>(op);
}

std::optional<component::Cleartext> Botan::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    return Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt>(op);
}

std::optional<component::Key> Botan::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            /* TODO remove once https://github.com/randombit/botan/issues/2088 has been addressed */
            CF_CHECK_GT(op.iterations, 0);

            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);
            std::string algoStringCopy = *algoString;
            if ( algoStringCopy == "SHAKE-128(128)" ) {
                algoStringCopy = "SHAKE-128(256)";
            } else if ( algoStringCopy == "SHAKE-256(256)" ) {
                algoStringCopy = "SHAKE-256(512)";
            }

            const std::string pbkdf2String = Botan_detail::parenthesize("PBKDF2", algoStringCopy);
            CF_CHECK_NE(pwdhash_fam = ::Botan::PasswordHashFamily::create(pbkdf2String), nullptr);

            CF_CHECK_NE(pwdhash = pwdhash_fam->from_params(op.iterations), nullptr);

        }

        /* Process */
        {
            pwdhash->derive_key(
                    out,
                    op.keySize,
                    (const char*)op.password.GetPtr(),
                    op.password.GetSize(),
                    op.salt.GetPtr(),
                    op.salt.GetSize());
        }

        /* Finalize */
        {
            ret = component::Key(out, op.keySize);
        }
    } catch ( ... ) { }

end:
    util::free(out);

    return ret;
}
} /* namespace module */
} /* namespace cryptofuzz */
