#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <botan/aead.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/cipher_mode.h>
#include <botan/curve25519.h>
#include <botan/dh.h>
#include <botan/ecdsa.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>
#include <botan/pubkey.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

Botan::Botan(void) :
    Module("Botan") {
    if ( setenv("BOTAN_MLOCK_POOL_SIZE", "0", 1) != 0 ) {
        abort();
    }
}

#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
 #define BOTAN_FUZZER_RNG Botan_detail::Fuzzer_RNG rng(ds);
#else
 #define BOTAN_FUZZER_RNG ::Botan::System_RNG rng;
#endif /* CRYPTOFUZZ_BOTAN_IS_ORACLE */

namespace Botan_detail {

#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
    class Fuzzer_RNG final : public ::Botan::RandomNumberGenerator {
        private:
            Datasource& ds;
        public:
            Fuzzer_RNG(Datasource& ds) :
                ds(ds)
            { }

            bool is_seeded() const override { return true; }

            bool accepts_input() const override { return false; }

            void clear() override {}

            virtual void randomize(uint8_t output[], size_t length) override {
                if ( length == 0 ) {
                    return;
                }

                const auto data = ds.GetData(0, length, length);

                memcpy(output, data.data(), length);
            }

            void add_entropy(const uint8_t[], size_t) override {
            }

            std::string name() const override { return "Fuzzer_RNG"; }
    };
#endif /* CRYPTOFUZZ_BOTAN_IS_ORACLE */

    const std::string parenthesize(const std::string parent, const std::string child) {
        static const std::string pOpen("(");
        static const std::string pClose(")");

        return parent + pOpen + child + pClose;
    }

    std::optional<std::string> DigestIDToString(const uint64_t digestType, const bool altShake = false, const bool isHmac = false) {
#include "digest_string_lut.h"
        std::optional<std::string> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(digestType), LUT.end());

        if ( isHmac == false ) {
            if (    digestType == CF_DIGEST("SIPHASH64") ||
                    digestType == CF_DIGEST("SIPHASH128") ) {
                return std::nullopt;
            }
        }
        if ( altShake == true && digestType == CF_DIGEST("SHAKE128") ) {
            ret = "SHAKE-128(256)";
        } else if ( altShake == true && digestType == CF_DIGEST("SHAKE256") ) {
            ret = "SHAKE-256(512)";
        } else {
            ret = LUT.at(digestType);
        }
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
#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
                clear = ds.Get<bool>();
#endif /* CRYPTOFUZZ_BOTAN_IS_ORACLE */
            } catch ( ... ) { }
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
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get(), true, true), std::nullopt);

            std::string hmacString;
            if (
                    op.digestType.Is(CF_DIGEST("SIPHASH64")) ||
                    op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
                hmacString = *algoString;
            } else {
                hmacString = Botan_detail::parenthesize("HMAC", *algoString);
            }

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

    std::optional<std::string> CipherIDToString(const uint64_t digestType, const bool withMode = true) {
#include "cipher_string_lut.h"
        std::optional<std::string> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(digestType), LUT.end());
        ret = withMode ? LUT.at(digestType).first : LUT.at(digestType).second;
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
    ::Botan::Cipher_Dir GetCryptType(void);

    template <>
    ::Botan::Cipher_Dir GetCryptType<operation::SymmetricEncrypt>(void) {
        return ::Botan::ENCRYPTION;
    }

    template <>
    ::Botan::Cipher_Dir GetCryptType<operation::SymmetricDecrypt>(void) {
        return ::Botan::DECRYPTION;
    }

    template <class OperationType>
    std::optional<size_t> GetTagSize(const OperationType& op);

    template <>
    std::optional<size_t> GetTagSize<>(const operation::SymmetricEncrypt& op) {
        if ( op.tagSize == std::nullopt ) {
            return std::nullopt;
        }

        return *op.tagSize;
    }

    template <>
    std::optional<size_t> GetTagSize<>(const operation::SymmetricDecrypt& op) {
        if ( op.tag == std::nullopt ) {
            return std::nullopt;
        }

        return op.tag->GetSize();
    }

    template <class OperationType>
    const uint8_t* GetTagPtr(const OperationType& op);

    template <>
    const uint8_t* GetTagPtr<>(const operation::SymmetricEncrypt& op) {
        (void)op;

        return nullptr;
    }

    template <>
    const uint8_t* GetTagPtr<>(const operation::SymmetricDecrypt& op) {
        if ( op.tag == std::nullopt ) {
            return nullptr;
        }

        return op.tag->GetPtr();
    }

    template <class CryptClass>
    void SetAAD(std::shared_ptr<CryptClass> crypt, const std::optional<component::AAD>& aad);

    template <>
    void SetAAD<>(std::shared_ptr<::Botan::AEAD_Mode> crypt, const std::optional<component::AAD>& aad) {
        if ( aad != std::nullopt ) {
            crypt->set_ad(aad->Get());
        }
    }

    template <>
    void SetAAD<>(std::shared_ptr<::Botan::Cipher_Mode> crypt, const std::optional<component::AAD>& aad) {
        (void)crypt;
        (void)aad;
    }

    template <class OperationType>
    ::Botan::secure_vector<uint8_t> GetInData(const OperationType& op) {
        ::Botan::secure_vector<uint8_t> ret(GetInPtr(op), GetInPtr(op) + GetInSize(op));

        if ( GetCryptType<OperationType>() == ::Botan::ENCRYPTION ) {
            return ret;
        }

        const auto tagSize = GetTagSize(op);

        if ( tagSize == std::nullopt || *tagSize == 0 ) {
            return ret;
        }

        /* Append the tag */

        ret.resize(ret.size() + *tagSize);

        memcpy(ret.data() + GetInSize(op), GetTagPtr(op), *tagSize);

        return ret;
    }

    template <class ReturnType>
    ReturnType ToReturnType(const ::Botan::secure_vector<uint8_t>& data, std::optional<size_t> tagSize);

    template <>
    component::Ciphertext ToReturnType(const ::Botan::secure_vector<uint8_t>& data, std::optional<size_t> tagSize) {
        if ( tagSize == std::nullopt ) {
            return component::Ciphertext(Buffer(data.data(), data.size()));
        }

        const size_t ciphertextSize = data.size() - *tagSize;

        return component::Ciphertext(Buffer(data.data(), ciphertextSize), Buffer(data.data() + ciphertextSize, *tagSize));
    }

    template <>
    component::Cleartext ToReturnType(const ::Botan::secure_vector<uint8_t>& data, std::optional<size_t> tagSize) {
        (void)tagSize;

        return component::Cleartext(Buffer(data.data(), data.size()));
    }

    template <class ReturnType, class OperationType, class CryptClass>
        std::optional<ReturnType> Crypt(OperationType& op) {
            std::optional<ReturnType> ret = std::nullopt;

            if ( typeid(CryptClass) == typeid(::Botan::Cipher_Mode) ) {
                if ( op.aad != std::nullopt ) {
                    return std::nullopt;
                }
                if ( GetTagSize(op) != std::nullopt ) {
                    return std::nullopt;
                }
            }

            Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

            std::shared_ptr<CryptClass> crypt = nullptr;
            const ::Botan::SymmetricKey key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            const ::Botan::InitializationVector iv(op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
            ::Botan::secure_vector<uint8_t> in = GetInData(op);
            std::vector<uint8_t> out;
            bool useOneShot = true;
            util::Multipart parts;

            const std::optional<size_t> tagSize = GetTagSize(op);

            try {
                /* Initialize */
                {
                    std::optional<std::string> _algoString;
                    CF_CHECK_NE(_algoString = Botan_detail::CipherIDToString(op.cipher.cipherType.Get()), std::nullopt);
                    std::string algoString;
                    if ( tagSize == std::nullopt ) {
                        algoString = Botan_detail::parenthesize(*_algoString, std::to_string(0));
                    } else {
                        algoString = Botan_detail::parenthesize(*_algoString, std::to_string(*tagSize));
                    }

                    CF_CHECK_NE(crypt = CryptClass::create(algoString, GetCryptType<OperationType>()), nullptr);
                    crypt->set_key(key);

                    SetAAD(crypt, op.aad);

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
                        ret = ToReturnType<ReturnType>(in, tagSize);
                    } else {
                        ret = ToReturnType<ReturnType>(::Botan::secure_vector<uint8_t>(out.data(), out.data() + out.size()), tagSize);
                    }
                }
            } catch ( ... ) { }
end:

            return ret;
        }

} /* namespace Botan_detail */

std::optional<component::MAC> Botan::OpCMAC(operation::CMAC& op) {
    (void)op;

    return std::nullopt;
#if 0
    if ( op.cipher.cipherType.Get() != CF_CIPHER("AES_128_CBC") ) {
        return {};
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;
    std::unique_ptr<::Botan::CMAC> cmac = nullptr;
    std::unique_ptr<::Botan::BlockCipher> cipher = nullptr;
    util::Multipart parts;

    const ::Botan::SymmetricKey key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());

    try {
        /* Initialize */
        {
            {
                std::optional<std::string> algoString;
                CF_CHECK_NE(algoString = Botan_detail::CipherIDToString(op.cipher.cipherType.Get(), false), std::nullopt);

                CF_CHECK_NE(cipher = ::Botan::BlockCipher::create(*algoString), nullptr);
            }

            CF_CHECK_NE(cmac = std::make_unique<::Botan::CMAC>(cipher->clone()), nullptr);
            cmac->set_key(key);

            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            cmac->update(part.first, part.second);
        }

        /* Finalize */
        {
            const auto res = cmac->final();
            ret = component::MAC(res.data(), res.size());
        }

    } catch ( ... ) { }

end:
    return ret;
#endif
}

std::optional<component::Ciphertext> Botan::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) && op.cipher.iv.GetSize() == 24 ) {
        /* Botan interpretes CHACHA20_POLY1305 + 192 bits IV as XCHACHA20_POLY1305 */
        return std::nullopt;
    }

    if ( cryptofuzz::repository::IsAEAD(op.cipher.cipherType.Get()) ) {
        return Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt, ::Botan::AEAD_Mode>(op);
    } else {
        return Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt, ::Botan::Cipher_Mode>(op);
    }
}

std::optional<component::Cleartext> Botan::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) && op.cipher.iv.GetSize() == 24 ) {
        return std::nullopt;
    }

    if ( cryptofuzz::repository::IsAEAD(op.cipher.cipherType.Get()) ) {
        return Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt, ::Botan::AEAD_Mode>(op);
    } else {
        return Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt, ::Botan::Cipher_Mode>(op);
    }
}

std::optional<component::Key> Botan::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            CF_CHECK_NE(pwdhash_fam = ::Botan::PasswordHashFamily::create("Scrypt"), nullptr);
            CF_CHECK_NE(pwdhash = pwdhash_fam->from_params(op.N, op.r, op.p), nullptr);

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

std::optional<component::Key> Botan::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::KDF> hkdf = nullptr;

    try {
        {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get(), true), std::nullopt);

            const std::string hkdfString = Botan_detail::parenthesize("HKDF", *algoString);
            hkdf = ::Botan::KDF::create(hkdfString);
        }

        {
            auto derived = hkdf->derive_key(op.keySize, op.password.Get(), op.salt.Get(), op.info.Get());

            ret = component::Key(derived.data(), derived.size());
        }
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::Key> Botan::OpKDF_PBKDF1(operation::KDF_PBKDF1& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PBKDF> pbkdf1 = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get(), true), std::nullopt);

            const std::string pbkdf1String = Botan_detail::parenthesize("PBKDF1", *algoString);
            CF_CHECK_NE(pbkdf1 = ::Botan::PBKDF::create(pbkdf1String), nullptr);
        }

        /* Process */
        {
            const std::string passphrase(op.password.GetPtr(), op.password.GetPtr() + op.password.GetSize());
            pbkdf1->pbkdf_iterations(
                    out,
                    op.keySize,
                    passphrase,
                    op.salt.GetPtr(),
                    op.salt.GetSize(),
                    op.iterations);
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

std::optional<component::Key> Botan::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get(), true), std::nullopt);

            const std::string pbkdf2String = Botan_detail::parenthesize("PBKDF2", *algoString);
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

std::optional<component::Key> Botan::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            std::string argon2String;

            switch ( op.type ) {
                case    0:
                    argon2String = "Argon2d";
                    break;
                case    1:
                    argon2String = "Argon2i";
                    break;
                case    2:
                    argon2String = "Argon2id";
                    break;
                default:
                    goto end;
            }
            CF_CHECK_NE(pwdhash_fam = ::Botan::PasswordHashFamily::create(argon2String), nullptr);

            CF_CHECK_NE(pwdhash = pwdhash_fam->from_params(
                        op.memory,
                        op.iterations,
                        op.threads), nullptr);
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

std::optional<component::Key> Botan::OpKDF_SP_800_108(operation::KDF_SP_800_108& op) {
    std::optional<component::Key> ret = std::nullopt;
    uint8_t* out = util::malloc(op.keySize);
    std::unique_ptr<::Botan::KDF> sp_800_108 = nullptr;

    try {
        std::optional<std::string> algoString;
        CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.mech.type.Get(), true), std::nullopt);

        const std::string hmacString = Botan_detail::parenthesize("HMAC", *algoString);
        std::string sp_800_108_string;
        switch ( op.mode ) {
            case    0:
                sp_800_108_string = Botan_detail::parenthesize("SP800-108-Counter", hmacString);
                break;
            case    1:
                sp_800_108_string = Botan_detail::parenthesize("SP800-108-Feedback", hmacString);
                break;
            case    2:
                sp_800_108_string = Botan_detail::parenthesize("SP800-108-Pipeline", hmacString);
                break;
            default:
                goto end;
        }

        sp_800_108 = ::Botan::KDF::create(sp_800_108_string);

        {
            auto derived = sp_800_108->derive_key(op.keySize, op.secret.Get(), op.salt.Get(), op.label.Get());

            ret = component::Key(derived.data(), derived.size());
        }
    } catch ( ... ) { }

end:

    util::free(out);
    return ret;
}

std::optional<component::Key> Botan::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::KDF> tlsprf = nullptr;

    try {
        {
            CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("MD5_SHA1"));
            CF_CHECK_NE(tlsprf = ::Botan::KDF::create("TLS-PRF()"), nullptr);
        }

        {
            const auto derived = tlsprf->derive_key(op.keySize, op.secret.Get(), op.seed.Get(), std::vector<uint8_t>{});

            ret = component::Key(derived.data(), derived.size());
        }
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::Key> Botan::OpKDF_BCRYPT(operation::KDF_BCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("SHA512"));
            CF_CHECK_NE(pwdhash_fam = ::Botan::PasswordHashFamily::create("Bcrypt-PBKDF"), nullptr);
            CF_CHECK_NE(pwdhash = pwdhash_fam->from_params(op.iterations), nullptr);

        }

        /* Process */
        {
            pwdhash->derive_key(
                    out,
                    op.keySize,
                    (const char*)op.secret.GetPtr(),
                    op.secret.GetSize(),
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

namespace Botan_detail {
    std::optional<std::string> CurveIDToString(const uint64_t curveID) {
#include "curve_string_lut.h"
        std::optional<std::string> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(curveID), LUT.end());
        ret = LUT.at(curveID);
end:
        return ret;
    }
} /* namespace Botan_detail */

std::optional<component::ECC_KeyPair> Botan::OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) {
    std::optional<component::ECC_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::string> curveString;
    BOTAN_FUZZER_RNG;

    CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);

    try {
        ::Botan::EC_Group group(*curveString);
        auto priv = ::Botan::ECDSA_PrivateKey(rng, group);

        const auto pub_x = priv.public_point().get_affine_x();
        const auto pub_y = priv.public_point().get_affine_y();

        {
            const auto pub = std::make_unique<::Botan::ECDSA_PublicKey>(::Botan::ECDSA_PublicKey(group, priv.public_point()));
            CF_ASSERT(pub->check_key(rng, true) == true, "Generated pubkey fails validation");
        }

        ret = { priv.private_value().to_dec_string(), { pub_x.to_dec_string(), pub_y.to_dec_string() } };

      /* Catch exception thrown from Botan_detail::Fuzzer_RNG::randomize */
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

end:
    return ret;
}

std::optional<bool> Botan::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;
    std::unique_ptr<::Botan::Public_Key> pub = nullptr;

    try {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);

        ::Botan::EC_Group group(*curveString);
        const ::Botan::BigInt pub_x(op.pub.first.ToString(ds));
        const ::Botan::BigInt pub_y(op.pub.second.ToString(ds));
        const ::Botan::PointGFp public_point = group.point(pub_x, pub_y);
        pub = std::make_unique<::Botan::ECDSA_PublicKey>(::Botan::ECDSA_PublicKey(group, public_point));

        ret = pub->check_key(rng, true);
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::ECC_PublicKey> Botan::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    try {
        std::optional<std::string> curveString;

        /* Botan appears to generate a new key if the input key is 0, so don't do this */
        CF_CHECK_NE(op.priv.ToTrimmedString(), "0");

        if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
            uint8_t priv_bytes[32];

            ::Botan::BigInt priv_bigint(op.priv.ToString(ds));
            priv_bigint.binary_encode(priv_bytes, sizeof(priv_bytes));
            priv_bytes[0] &= 248;
            priv_bytes[31] &= 127;
            priv_bytes[31] |= 64;
            const ::Botan::secure_vector<uint8_t> priv_vec(priv_bytes, priv_bytes + sizeof(priv_bytes));

            auto priv = ::Botan::X25519_PrivateKey(priv_vec);

            ::Botan::BigInt pub;
            pub.binary_decode(priv.public_value());

            ret = { pub.to_dec_string(), "0" };
        } else {
            CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
            ::Botan::EC_Group group(*curveString);

            const ::Botan::BigInt priv_bn(op.priv.ToString(ds));
            auto priv = std::make_unique<::Botan::ECDSA_PrivateKey>(::Botan::ECDSA_PrivateKey(rng, group, priv_bn));

            const auto pub_x = priv->public_point().get_affine_x();
            const auto pub_y = priv->public_point().get_affine_y();

            ret = { pub_x.to_dec_string(), pub_y.to_dec_string() };
        }
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::ECDSA_Signature> Botan::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<::Botan::ECDSA_PrivateKey> priv = nullptr;
    std::unique_ptr<::Botan::Public_Key> pub = nullptr;
    std::unique_ptr<::Botan::PK_Signer> signer;

    BOTAN_FUZZER_RNG;

    CF_CHECK_EQ(op.UseRFC6979Nonce(), true);
    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("SHA256"));

    try {
        /* Initialize */
        {
            std::optional<std::string> curveString, algoString;

            /* Botan appears to generate a new key if the input key is 0, so don't do this */
            CF_CHECK_NE(op.priv.ToTrimmedString(), "0");

            CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
            ::Botan::EC_Group group(*curveString);

            /* Private key */
            {
                const ::Botan::BigInt priv_bn(op.priv.ToString(ds));
                priv = std::make_unique<::Botan::ECDSA_PrivateKey>(::Botan::ECDSA_PrivateKey(rng, group, priv_bn));
            }

            /* Prepare signer */
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);

            const std::string emsa1String = Botan_detail::parenthesize("EMSA1", *algoString);
            signer.reset(new ::Botan::PK_Signer(*priv, rng, emsa1String, ::Botan::DER_SEQUENCE));
        }

        /* Process */
        {
            const auto signature = signer->sign_message(op.cleartext.Get(), rng);

            /* Retrieve R and S */
            {
                ::Botan::BER_Decoder decoder(signature);
                ::Botan::BER_Decoder ber_sig = decoder.start_sequence();

                size_t count = 0;

                ::Botan::BigInt R;
                ::Botan::BigInt S;
                while(ber_sig.more_items())
                {
                    switch ( count ) {
                        case    0:
                            ber_sig.decode(R);
                            break;
                        case    1:
                            ber_sig.decode(S);
                            break;
                        default:
                            printf("Error: Too many parts in signature BER\n");
                            abort();
                    }

                    ++count;
                }

                if ( op.curveType.Get() == CF_ECC_CURVE("secp256k1") ) {
                    /* For compatibility with the secp256k1 library.
                     * See: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
                     */
                    if (S > ::Botan::BigInt("57896044618658097711785492504343953926418782139537452191302581570759080747168")) {
                        S = ::Botan::BigInt("115792089237316195423570985008687907852837564279074904382605163141518161494337") - S;
                    }
                } else if ( op.curveType.Get() == CF_ECC_CURVE("secp256r1") ) {
                    /* Similar ECDSA signature malleability adjustment for compatibility with trezor-firmware */
                    if (S > ::Botan::BigInt("57896044605178124381348723474703786764998477612067880171211129530534256022184")) {
                        S = ::Botan::BigInt("115792089210356248762697446949407573529996955224135760342422259061068512044369") - S;
                    }
                }

                const auto pub_x = priv->public_point().get_affine_x().to_dec_string();
                const auto pub_y = priv->public_point().get_affine_y().to_dec_string();

                const auto R_str = R.to_dec_string();
                const auto S_str = S.to_dec_string();

                ret = component::ECDSA_Signature({ R_str, S_str }, { pub_x, pub_y });
            }
        }
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<bool> Botan::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<::Botan::Public_Key> pub = nullptr;

    try {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        ::Botan::EC_Group group(*curveString);

        {
            const ::Botan::BigInt pub_x(op.signature.pub.first.ToString(ds));
            const ::Botan::BigInt pub_y(op.signature.pub.second.ToString(ds));
            const ::Botan::PointGFp public_point = group.point(pub_x, pub_y);
            pub = std::make_unique<::Botan::ECDSA_PublicKey>(::Botan::ECDSA_PublicKey(group, public_point));
        }

        ::Botan::PK_Verifier verifier(*pub, "Raw");

        std::vector<uint8_t> CT;
        if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
            CT = op.cleartext.Get();
        } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);

            auto hash = ::Botan::HashFunction::create(*algoString);
            hash->update(op.cleartext.GetPtr(), op.cleartext.GetSize());
            const auto _CT = hash->final();
            CT = {_CT.data(), _CT.data() + _CT.size()};
        } else {
            /* TODO other digests */
            goto end;
        }

        const ::Botan::BigInt R(op.signature.signature.first.ToString(ds));
        const ::Botan::BigInt S(op.signature.signature.second.ToString(ds));

        /* XXX may throw: Encoding error: encode_fixed_length_int_pair: values too large to encode properly */
        auto sig = ::Botan::BigInt::encode_fixed_length_int_pair(R, S, group.get_order_bytes());

        ret = verifier.verify_message(CT, sig);
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::Bignum> Botan::OpDH_Derive(operation::DH_Derive& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    try {
        CF_CHECK_NE(op.priv.ToTrimmedString(), "0");

        const ::Botan::BigInt g(op.base.ToString(ds));
        const ::Botan::BigInt p(op.prime.ToString(ds));
        const ::Botan::DL_Group grp(p, g);

        const ::Botan::BigInt _priv(op.priv.ToString(ds));
        std::unique_ptr<::Botan::Private_Key> priv(new ::Botan::DH_PrivateKey(rng, grp, _priv));

        const ::Botan::BigInt _pub(op.pub.ToString(ds));
        ::Botan::DH_PublicKey pub(grp, _pub);

        std::unique_ptr<::Botan::PK_Key_Agreement> kas(new ::Botan::PK_Key_Agreement(*priv, rng, "Raw"));
        const auto derived_key = kas->derive_key(0, pub.public_value());

        const auto derived_str = ::Botan::BigInt(derived_key.bits_of()).to_dec_string();
        if ( derived_str != "0" ) {
            ret = derived_str;
        }
    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::Bignum> Botan::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ::Botan::BigInt res("0");
    std::vector<::Botan::BigInt> bn{
        ::Botan::BigInt(op.bn0.ToString(ds)),
        ::Botan::BigInt(op.bn1.ToString(ds)),
        ::Botan::BigInt(op.bn2.ToString(ds)),
        ::Botan::BigInt(op.bn3.ToString(ds))
    };
    std::unique_ptr<Botan_bignum::Operation> opRunner = nullptr;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Div>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            /* Too slow with larger values */
            CF_CHECK_LT(op.bn0.GetSize(), 1000);
            CF_CHECK_LT(op.bn1.GetSize(), 1000);
            CF_CHECK_LT(op.bn2.GetSize(), 1000);

            opRunner = std::make_unique<Botan_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<Botan_bignum::Sqr>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<Botan_bignum::GCD>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<Botan_bignum::SqrMod>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<Botan_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Cmp>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<Botan_bignum::LCM>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<Botan_bignum::Abs>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<Botan_bignum::Neg>();
            break;
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<Botan_bignum::IsPrime>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<Botan_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<Botan_bignum::LShift1>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<Botan_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<Botan_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<Botan_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<Botan_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<Botan_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<Botan_bignum::IsOne>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::MulMod>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Bit>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<Botan_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<Botan_bignum::SetBit>();
            break;
        case    CF_CALCOP("Mod_NIST_192(A)"):
            opRunner = std::make_unique<Botan_bignum::Mod_NIST_192>();
            break;
        case    CF_CALCOP("Mod_NIST_224(A)"):
            opRunner = std::make_unique<Botan_bignum::Mod_NIST_224>();
            break;
        case    CF_CALCOP("Mod_NIST_256(A)"):
            opRunner = std::make_unique<Botan_bignum::Mod_NIST_256>();
            break;
        case    CF_CALCOP("Mod_NIST_384(A)"):
            opRunner = std::make_unique<Botan_bignum::Mod_NIST_384>();
            break;
        case    CF_CALCOP("Mod_NIST_521(A)"):
            opRunner = std::make_unique<Botan_bignum::Mod_NIST_521>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<Botan_bignum::ClearBit>();
            break;
        case    CF_CALCOP("MulAdd(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::MulAdd>();
            break;
        case    CF_CALCOP("Exp2(A)"):
            opRunner = std::make_unique<Botan_bignum::Exp2>();
            break;
        case    CF_CALCOP("NumLSZeroBits(A)"):
            opRunner = std::make_unique<Botan_bignum::NumLSZeroBits>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<Botan_bignum::Sqrt>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::SubMod>();
            break;
        case    CF_CALCOP("NumBits(A)"):
            opRunner = std::make_unique<Botan_bignum::NumBits>();
            break;
        case    CF_CALCOP("Set(A)"):
            opRunner = std::make_unique<Botan_bignum::Set>();
            break;
        case    CF_CALCOP("CondSet(A,B)"):
            opRunner = std::make_unique<Botan_bignum::CondSet>();
            break;
        case    CF_CALCOP("Ressol(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Ressol>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);

    try {
        CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);
    } catch ( ... ) {
        goto end;
    }

    ret = { res.is_negative() ?
            ("-" + util::HexToDec(res.to_hex_string())) :
            util::HexToDec(res.to_hex_string()) };

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
