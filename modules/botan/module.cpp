#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <botan/aead.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/cipher_mode.h>
#include <botan/curve25519.h>
#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/ecgdsa.h>
#include <botan/ed25519.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
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

#if !defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
 #define BOTAN_SET_GLOBAL_DS CF_NORET(util::SetGlobalDs(&ds));
 #define BOTAN_UNSET_GLOBAL_DS CF_NORET(util::UnsetGlobalDs());
#else
 #define BOTAN_SET_GLOBAL_DS
 #define BOTAN_UNSET_GLOBAL_DS
#endif

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

            virtual void fill_bytes_with_input(
                    std::span<uint8_t> output,
                    std::span<const uint8_t> input) override {
                (void)input;

                if ( output.empty() ) {
                    return;
                }

                const auto data = ds.GetData(0, output.size(), output.size());

                std::copy(data.begin(), data.end(), output.begin());
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
        } else if ( altShake == true && digestType == CF_DIGEST("SHAKE256_114") ) {
            ret = "SHAKE-256(912)"; /* 114 bytes * 8 = 912 bits */
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
        BOTAN_SET_GLOBAL_DS

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
    BOTAN_UNSET_GLOBAL_DS

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
            BOTAN_SET_GLOBAL_DS

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
    BOTAN_UNSET_GLOBAL_DS

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
        return ::Botan::Cipher_Dir::Encryption;
    }

    template <>
    ::Botan::Cipher_Dir GetCryptType<operation::SymmetricDecrypt>(void) {
        return ::Botan::Cipher_Dir::Decryption;
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
            crypt->set_associated_data(aad->Get());
        }
    }

    template <>
    void SetAAD<>(std::shared_ptr<::Botan::Cipher_Mode> crypt, const std::optional<component::AAD>& aad) {
        (void)crypt;
        (void)aad;
    }

    template <class OperationType>
    ::Botan::secure_vector<uint8_t> GetInData(const OperationType& op) {
        const auto inPtr = GetInPtr(op);
        ::Botan::secure_vector<uint8_t> ret(inPtr, inPtr + GetInSize(op));

        if ( GetCryptType<OperationType>() == ::Botan::Cipher_Dir::Encryption ) {
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
        std::optional<ReturnType> Crypt(OperationType& op, Datasource& ds) {
            std::optional<ReturnType> ret = std::nullopt;

            if ( typeid(CryptClass) == typeid(::Botan::Cipher_Mode) ) {
                if ( op.aad != std::nullopt ) {
                    return std::nullopt;
                }
                if ( GetTagSize(op) != std::nullopt ) {
                    return std::nullopt;
                }
            }

            std::shared_ptr<CryptClass> crypt = nullptr;
            const ::Botan::SymmetricKey key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            const ::Botan::InitializationVector iv(op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
            ::Botan::secure_vector<uint8_t> in = GetInData(op);
            ::Botan::secure_vector<uint8_t> out;
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
                            const auto num = crypt->process(tmp.data(), tmp.size());
                            out.insert(out.end(), tmp.begin(), tmp.begin() + num);
                        }
                        crypt->finish(out, out.size());
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
    if ( !repository::IsCBC(op.cipher.cipherType.Get()) ) {
        return std::nullopt;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;
    std::unique_ptr<::Botan::MessageAuthenticationCode> cmac = nullptr;
    util::Multipart parts;

    try {
        /* Initialize */
        {
            BOTAN_SET_GLOBAL_DS

            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::CipherIDToString(op.cipher.cipherType.Get(), false), std::nullopt);

            const std::string cmacString = Botan_detail::parenthesize("CMAC", *algoString);

            CF_CHECK_NE(cmac = ::Botan::MessageAuthenticationCode::create(cmacString), nullptr);

            try {
                cmac->set_key(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } catch ( ... ) {
                goto end;
            }

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
    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Ciphertext> Botan::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) && op.cipher.iv.GetSize() == 24 ) {
        /* Botan interpretes CHACHA20_POLY1305 + 192 bits IV as XCHACHA20_POLY1305 */
        return std::nullopt;
    }

    std::optional<component::Ciphertext> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    BOTAN_SET_GLOBAL_DS

    if ( cryptofuzz::repository::IsAEAD(op.cipher.cipherType.Get()) ) {
        ret = Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt, ::Botan::AEAD_Mode>(op, ds);
    } else {
        ret = Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt, ::Botan::Cipher_Mode>(op, ds);
    }

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Cleartext> Botan::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) && op.cipher.iv.GetSize() == 24 ) {
        return std::nullopt;
    }

    std::optional<component::Cleartext> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    BOTAN_SET_GLOBAL_DS

    if ( cryptofuzz::repository::IsAEAD(op.cipher.cipherType.Get()) ) {
        ret = Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt, ::Botan::AEAD_Mode>(op, ds);
    } else {
        ret = Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt, ::Botan::Cipher_Mode>(op, ds);
    }

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            BOTAN_SET_GLOBAL_DS

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

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::KDF> hkdf = nullptr;

    try {
        {
            BOTAN_SET_GLOBAL_DS

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
    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            BOTAN_SET_GLOBAL_DS

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

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        /* Initialize */
        {
            BOTAN_SET_GLOBAL_DS

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

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_SP_800_108(operation::KDF_SP_800_108& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    uint8_t* out = util::malloc(op.keySize);
    std::unique_ptr<::Botan::KDF> sp_800_108 = nullptr;

    try {
        BOTAN_SET_GLOBAL_DS

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

    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::KDF> tlsprf = nullptr;

    try {
        BOTAN_SET_GLOBAL_DS

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
    BOTAN_UNSET_GLOBAL_DS

    return ret;
}

std::optional<component::Key> Botan::OpKDF_BCRYPT(operation::KDF_BCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<::Botan::PasswordHashFamily> pwdhash_fam = nullptr;
    std::unique_ptr<::Botan::PasswordHash> pwdhash = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    try {
        BOTAN_SET_GLOBAL_DS

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

    BOTAN_UNSET_GLOBAL_DS

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

        if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
            uint8_t priv_bytes[32];

            const ::Botan::BigInt priv_bigint(op.priv.ToString(ds));
            CF_CHECK_GT(priv_bigint, 0);

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
            CF_CHECK_GT(priv_bn, 0);

            auto priv = std::make_unique<::Botan::ECDSA_PrivateKey>(::Botan::ECDSA_PrivateKey(rng, group, priv_bn));

            const auto pub_x = priv->public_point().get_affine_x();
            const auto pub_y = priv->public_point().get_affine_y();

            ret = { pub_x.to_dec_string(), pub_y.to_dec_string() };
        }
    } catch ( ... ) { }

end:
    return ret;
}

namespace Botan_detail {
    template <class PrivkeyType, class Operation, bool RFC6979 = true>
        std::optional<component::ECDSA_Signature> ECxDSA_Sign(Operation& op) {
            std::optional<component::ECDSA_Signature> ret = std::nullopt;
            Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

            std::unique_ptr<PrivkeyType> priv = nullptr;
            std::unique_ptr<::Botan::Public_Key> pub = nullptr;
            std::unique_ptr<::Botan::PK_Signer> signer;

            BOTAN_FUZZER_RNG;

            BOTAN_SET_GLOBAL_DS

            if ( RFC6979 == true ) {
                CF_CHECK_EQ(op.UseRFC6979Nonce(), true);
            } else {
                CF_CHECK_EQ(op.UseRandomNonce(), true);
            }

            CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("SHA256"));

            try {
                /* Initialize */
                {

                    std::optional<std::string> curveString, algoString;

                    CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
                    ::Botan::EC_Group group(*curveString);

                    /* Private key */
                    {
                        const ::Botan::BigInt priv_bn(op.priv.ToString(ds));

                        /* Botan appears to generate a new key if the input key is 0,
                         * so don't do this */
                        CF_CHECK_NE(priv_bn, 0);

                        priv = std::make_unique<PrivkeyType>(PrivkeyType(rng, group, priv_bn));
                    }

                    /* Prepare signer */
                    CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);

                    const std::string emsa1String = Botan_detail::parenthesize("EMSA1", *algoString);
                    signer.reset(new ::Botan::PK_Signer(*priv, rng, emsa1String, ::Botan::Signature_Format::DerSequence));
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
            BOTAN_UNSET_GLOBAL_DS

            return ret;
        }
} /* namespace Botan_detail */

std::optional<component::ECDSA_Signature> Botan::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        const auto _priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
        if ( _priv_bytes == std::nullopt ) {
            return std::nullopt;
        }

        const ::Botan::secure_vector<uint8_t> priv_bytes(_priv_bytes->data(), _priv_bytes->data() + _priv_bytes->size());

        const auto priv = std::make_unique<::Botan::Ed25519_PrivateKey>(priv_bytes);

        std::unique_ptr<::Botan::PK_Signer> signer;

        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        BOTAN_FUZZER_RNG;

        signer.reset(new ::Botan::PK_Signer(*priv, rng, "Pure", ::Botan::Signature_Format::Standard));

        const auto signature = signer->sign_message(op.cleartext.Get(), rng);
        CF_ASSERT(signature.size() == 64, "ed25519 signature is not 64 bytes");

        const auto pub = priv->get_public_key();
        CF_ASSERT(pub.size() == 32, "ed25519 pubkey is not 32 bytes");

        const auto ret = component::ECDSA_Signature(
                { util::BinToDec(signature.data(), 32), util::BinToDec(signature.data() + 32, 32) },
                { util::BinToDec(pub.data(), 32), "0"}
        );

        return ret;
    }

    return Botan_detail::ECxDSA_Sign<::Botan::ECDSA_PrivateKey, operation::ECDSA_Sign>(op);
}

std::optional<component::ECGDSA_Signature> Botan::OpECGDSA_Sign(operation::ECGDSA_Sign& op) {
    return Botan_detail::ECxDSA_Sign<::Botan::ECGDSA_PrivateKey, operation::ECGDSA_Sign, false>(op);
}

namespace Botan_detail {
    template <class PubkeyType, class Operation>
        std::optional<bool> ECxDSA_Verify(Operation& op) {
            std::optional<bool> ret = std::nullopt;
            Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

            ::Botan::secure_vector<uint8_t> sig;
            std::unique_ptr<::Botan::Public_Key> pub = nullptr;
            std::unique_ptr<::Botan::EC_Group> group = nullptr;
            Buffer CT;

            {
                BOTAN_SET_GLOBAL_DS

                std::optional<std::string> curveString;
                CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
                group = std::make_unique<::Botan::EC_Group>(*curveString);
            }

            /* Construct signature */
            {
                const ::Botan::BigInt R(op.signature.signature.first.ToString(ds));
                const ::Botan::BigInt S(op.signature.signature.second.ToString(ds));
                try {
                    sig = ::Botan::BigInt::encode_fixed_length_int_pair(R, S, group->get_order_bytes());
                } catch ( ::Botan::Encoding_Error ) {
                    /* Invalid signature */
                    BOTAN_UNSET_GLOBAL_DS
                    return false;
                }
            }

            /* Construct pubkey */
            try {
                const ::Botan::BigInt pub_x(op.signature.pub.first.ToString(ds));
                const ::Botan::BigInt pub_y(op.signature.pub.second.ToString(ds));
                const ::Botan::PointGFp public_point = group->point(pub_x, pub_y);
                pub = std::make_unique<PubkeyType>(PubkeyType(*group, public_point));
            } catch ( ::Botan::Invalid_Argument ) {
                /* Invalid point */
                BOTAN_UNSET_GLOBAL_DS
                return false;
            }

            /* Construct input */
            {
                if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
                    CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
                } else {
                    std::optional<std::string> algoString;
                    CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);

                    auto hash = ::Botan::HashFunction::create(*algoString);
                    hash->update(op.cleartext.GetPtr(), op.cleartext.GetSize());
                    const auto _CT = hash->final();
                    CT = Buffer(_CT.data(), _CT.size()).ECDSA_RandomPad(ds, op.curveType);
                }
            }

            ret = ::Botan::PK_Verifier(*pub, "Raw").verify_message(CT.Get(), sig);

end:
            BOTAN_UNSET_GLOBAL_DS

            return ret;
        }
} /* namespace Botan_detail */

std::optional<bool> Botan::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ) {
        const auto pub_bytes = util::DecToBin(op.signature.pub.first.ToTrimmedString(), 32);
        if ( pub_bytes == std::nullopt ) {
            return std::nullopt;
        }
        const auto pub = std::make_unique<::Botan::Ed25519_PublicKey>(*pub_bytes);

        const auto sig_r = util::DecToBin(op.signature.signature.first.ToTrimmedString(), 32);
        if ( sig_r == std::nullopt ) {
            return std::nullopt;
        }

        const auto sig_s = util::DecToBin(op.signature.signature.second.ToTrimmedString(), 32);
        if ( sig_s == std::nullopt ) {
            return std::nullopt;
        }

        std::vector<uint8_t> sig_bytes(64);
        memcpy(sig_bytes.data(), sig_r->data(), 32);
        memcpy(sig_bytes.data() + 32, sig_s->data(), 32);

        const bool ret = ::Botan::PK_Verifier(*pub, "Pure").verify_message(op.cleartext.Get(), sig_bytes);
        return ret;

    } else {
        return Botan_detail::ECxDSA_Verify<::Botan::ECDSA_PublicKey, operation::ECDSA_Verify>(op);
    }
}

std::optional<bool> Botan::OpECGDSA_Verify(operation::ECGDSA_Verify& op) {
    return Botan_detail::ECxDSA_Verify<::Botan::ECGDSA_PublicKey, operation::ECGDSA_Verify>(op);
}

std::optional<component::ECC_PublicKey> Botan::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<::Botan::EC_Group> group = nullptr;
    Buffer CT;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    /* Construct input */
    {
        if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
            CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
        } else {
            std::optional<std::string> algoString;
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get()), std::nullopt);

            auto hash = ::Botan::HashFunction::create(*algoString);
            hash->update(op.cleartext.GetPtr(), op.cleartext.GetSize());
            const auto _CT = hash->final();
            CT = Buffer(_CT.data(), _CT.size()).ECDSA_RandomPad(ds, op.curveType);
        }
    }

    {
        const ::Botan::BigInt R(op.signature.first.ToString(ds));
        const ::Botan::BigInt S(op.signature.second.ToString(ds));

        std::unique_ptr<::Botan::ECDSA_PublicKey> pub = nullptr;
        try {
            pub = std::make_unique<::Botan::ECDSA_PublicKey>(*group, CT.Get(), R, S, op.id);

            ret = {
                pub->public_point().get_affine_x().to_dec_string(),
                pub->public_point().get_affine_y().to_dec_string()
            };
        } catch ( ::Botan::Invalid_State& e ) {
        } catch ( ::Botan::Decoding_Error& ) {
        } catch ( ::Botan::Invalid_Argument& ) {
            //ret = {"0", "0"};
        }

    }

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

        /* Prevent time-out */
        CF_CHECK_LT(g.bytes(), 80);
        CF_CHECK_LT(p.bytes(), 80);
        CF_CHECK_LT(_priv.bytes(), 80);

        std::unique_ptr<::Botan::Private_Key> priv(new ::Botan::DH_PrivateKey(grp, _priv));

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

std::optional<component::ECC_Point> Botan::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    std::unique_ptr<::Botan::EC_Group> group = nullptr;
    std::unique_ptr<::Botan::PointGFp> a, b;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    {
        /* A */
        {
            const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
            CF_CHECK_GTE(a_x, 0);

            const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
            CF_CHECK_GTE(a_y, 0);

            try {
                a = std::make_unique<::Botan::PointGFp>(group->point(a_x, a_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }
            CF_CHECK_TRUE(a->on_the_curve());
        }

        /* B */
        {
            const auto b_x = ::Botan::BigInt(op.b.first.ToString(ds));
            CF_CHECK_GTE(b_x, 0);

            const auto b_y = ::Botan::BigInt(op.b.second.ToString(ds));
            CF_CHECK_GTE(b_y, 0);

            try {
                b = std::make_unique<::Botan::PointGFp>(group->point(b_x, b_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }

            CF_CHECK_TRUE(b->on_the_curve());
        }

        const bool is_negation = *a == -(*b);

        ::Botan::PointGFp _res = *a + *b;

        const bool is_zero = _res.is_zero();

        /* If A is a negation of B, then addition of both should result in point at infinity */
        /* Otherwise, it should result in non-infinity. */
        CF_ASSERT(is_zero == is_negation, "Unexpected point addition result");
        CF_CHECK_FALSE(is_zero);

        const auto x = _res.get_affine_x();
        const auto y = _res.get_affine_y();

        ret = {
            util::HexToDec(x.to_hex_string()),
            util::HexToDec(y.to_hex_string()),
        };

    }

end:
    return ret;
}

std::optional<component::ECC_Point> Botan::OpECC_Point_Sub(operation::ECC_Point_Sub& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    std::unique_ptr<::Botan::EC_Group> group = nullptr;
    std::unique_ptr<::Botan::PointGFp> a, b;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    {
        /* A */
        {
            const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
            CF_CHECK_GTE(a_x, 0);

            const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
            CF_CHECK_GTE(a_y, 0);

            try {
                a = std::make_unique<::Botan::PointGFp>(group->point(a_x, a_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }
            CF_CHECK_TRUE(a->on_the_curve());
        }

        /* B */
        {
            const auto b_x = ::Botan::BigInt(op.b.first.ToString(ds));
            CF_CHECK_GTE(b_x, 0);

            const auto b_y = ::Botan::BigInt(op.b.second.ToString(ds));
            CF_CHECK_GTE(b_y, 0);

            try {
                b = std::make_unique<::Botan::PointGFp>(group->point(b_x, b_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }

            CF_CHECK_TRUE(b->on_the_curve());
        }

        const bool is_eq = *a == *b;

        ::Botan::PointGFp _res = *a - *b;

        const bool is_zero = _res.is_zero();

        /* If A equals B, then subtraction of both should result in point at infinity */
        /* Otherwise, it should result in non-infinity. */
        CF_ASSERT(is_zero == is_eq, "Unexpected point subtraction result");
        CF_CHECK_FALSE(is_zero);

        const auto x = _res.get_affine_x();
        const auto y = _res.get_affine_y();

        ret = {
            util::HexToDec(x.to_hex_string()),
            util::HexToDec(y.to_hex_string()),
        };

    }

end:
    return ret;
}

std::optional<component::ECC_Point> Botan::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    std::unique_ptr<::Botan::EC_Group> group = nullptr;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    try {
        const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
        CF_CHECK_GTE(a_x, 0);

        const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
        CF_CHECK_GTE(a_y, 0);

        const auto a = group->point(a_x, a_y);
        CF_CHECK_TRUE(a.on_the_curve());

        const auto b = ::Botan::BigInt(op.b.ToString(ds));

        CF_CHECK_GTE(b, 0);

        std::vector<::Botan::BigInt> ws(::Botan::PointGFp::WORKSPACE_SIZE);

        bool useBlinding = false;
#if defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
        try {
            useBlinding = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
#endif

        ::Botan::PointGFp _res;

        if ( useBlinding == false ) {
            _res = a * b;
        } else {
            _res = group->blinded_var_point_multiply(a, b, rng, ws);
        }

        const auto x = _res.get_affine_x();
        const auto y = _res.get_affine_y();

        ret = {
            util::HexToDec(x.to_hex_string()),
            util::HexToDec(y.to_hex_string()),
        };

    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::ECC_Point> Botan::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<::Botan::EC_Group> group = nullptr;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    try {
        const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
        CF_CHECK_GTE(a_x, 0);

        const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
        CF_CHECK_GTE(a_y, 0);

        const auto a = group->point(a_x, a_y);
        CF_CHECK_TRUE(a.on_the_curve());

        const ::Botan::PointGFp _res = -a;

        const auto x = _res.get_affine_x();
        const auto y = _res.get_affine_y();

        ret = {
            util::HexToDec(x.to_hex_string()),
            util::HexToDec(y.to_hex_string()),
        };

    } catch ( ... ) { }

end:
    return ret;
}

std::optional<component::ECC_Point> Botan::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<::Botan::EC_Group> group = nullptr;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    try {
        const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
        CF_CHECK_GTE(a_x, 0);

        const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
        CF_CHECK_GTE(a_y, 0);

        const auto a = group->point(a_x, a_y);
        CF_CHECK_TRUE(a.on_the_curve());

        const ::Botan::PointGFp _res = a + a;

        const auto x = _res.get_affine_x();
        const auto y = _res.get_affine_y();

        ret = {
            util::HexToDec(x.to_hex_string()),
            util::HexToDec(y.to_hex_string()),
        };

    } catch ( ... ) { }

end:
    return ret;
}

std::optional<bool> Botan::OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    BOTAN_FUZZER_RNG;

    std::unique_ptr<::Botan::EC_Group> group = nullptr;
    std::unique_ptr<::Botan::PointGFp> a, b;

    {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        group = std::make_unique<::Botan::EC_Group>(*curveString);
    }

    {
        /* A */
        {
            const auto a_x = ::Botan::BigInt(op.a.first.ToString(ds));
            CF_CHECK_GTE(a_x, 0);

            const auto a_y = ::Botan::BigInt(op.a.second.ToString(ds));
            CF_CHECK_GTE(a_y, 0);

            try {
                a = std::make_unique<::Botan::PointGFp>(group->point(a_x, a_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }
            CF_CHECK_TRUE(a->on_the_curve());
        }

        /* B */
        {
            const auto b_x = ::Botan::BigInt(op.b.first.ToString(ds));
            CF_CHECK_GTE(b_x, 0);

            const auto b_y = ::Botan::BigInt(op.b.second.ToString(ds));
            CF_CHECK_GTE(b_y, 0);

            try {
                b = std::make_unique<::Botan::PointGFp>(group->point(b_x, b_y));
            } catch ( ::Botan::Invalid_Argument ) {
                goto end;
            }

            CF_CHECK_TRUE(b->on_the_curve());
        }

        ret = *a == *b;
    }

end:
    return ret;
}

std::optional<bool> Botan::OpDSA_Verify(operation::DSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        const auto p = ::Botan::BigInt(op.parameters.p.ToString(ds));
        const auto q = ::Botan::BigInt(op.parameters.q.ToString(ds));
        const auto g = ::Botan::BigInt(op.parameters.g.ToString(ds));

        /* Botan can verify signatures with g = 0.
         * Avoid discrepancies with OpenSSL
         */
        CF_CHECK_NE(g, 0);

        const ::Botan::DL_Group group(p, q, g);

        const auto y = ::Botan::BigInt(op.pub.ToString(ds));
        const auto pub = std::make_unique<::Botan::DSA_PublicKey>(group, y);

        const auto r = ::Botan::BigInt(op.signature.first.ToString(ds));
        const auto s = ::Botan::BigInt(op.signature.second.ToString(ds));

        const auto sig = ::Botan::BigInt::encode_fixed_length_int_pair(
                r, s, q.bytes());
        auto verifier = ::Botan::PK_Verifier(*pub, "Raw");
        verifier.update(op.cleartext.Get());
        ret = verifier.check_signature(sig);
    } catch ( ... ) {
    }

end:
    return ret;
}

std::optional<component::Bignum> Botan::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.modulo ) {
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
            case    CF_CALCOP("Bit(A,B)"):
            case    CF_CALCOP("CondSet(A,B)"):
            case    CF_CALCOP("Exp(A,B)"):
            case    CF_CALCOP("InvMod(A,B)"):
            case    CF_CALCOP("IsEq(A,B)"):
            case    CF_CALCOP("IsEven(A)"):
            case    CF_CALCOP("IsOdd(A)"):
            case    CF_CALCOP("IsOne(A)"):
            case    CF_CALCOP("IsZero(A)"):
            case    CF_CALCOP("LShift1(A)"):
            case    CF_CALCOP("Mul(A,B)"):
            case    CF_CALCOP("Not(A)"):
            case    CF_CALCOP("NumBits(A)"):
            case    CF_CALCOP("RShift(A,B)"):
            case    CF_CALCOP("Set(A)"):
            case    CF_CALCOP("Sqr(A)"):
            case    CF_CALCOP("Sqrt(A)"):
            case    CF_CALCOP("Sub(A,B)"):
                break;
            default:
                return ret;
        }
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    Botan_bignum::Bignum res(&ds, "0");
    std::vector<Botan_bignum::Bignum> bn{
        Botan_bignum::Bignum(&ds, op.bn0.ToString(ds)),
        Botan_bignum::Bignum(&ds, op.bn1.ToString(ds)),
        Botan_bignum::Bignum(&ds, op.bn2.ToString(ds)),
        Botan_bignum::Bignum(&ds, op.bn3.ToString(ds))
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
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Exp>();
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
        case    CF_CALCOP("IsGt(A,B)"):
            opRunner = std::make_unique<Botan_bignum::IsGt>();
            break;
        case    CF_CALCOP("IsGte(A,B)"):
            opRunner = std::make_unique<Botan_bignum::IsGte>();
            break;
        case    CF_CALCOP("IsLt(A,B)"):
            opRunner = std::make_unique<Botan_bignum::IsLt>();
            break;
        case    CF_CALCOP("IsLte(A,B)"):
            opRunner = std::make_unique<Botan_bignum::IsLte>();
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
        case    CF_CALCOP("IsNotZero(A)"):
            opRunner = std::make_unique<Botan_bignum::IsNotZero>();
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
        case    CF_CALCOP("MulDiv(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::MulDiv>();
            break;
        case    CF_CALCOP("MulDivCeil(A,B,C)"):
            opRunner = std::make_unique<Botan_bignum::MulDivCeil>();
            break;
        case    CF_CALCOP("Exp2(A)"):
            opRunner = std::make_unique<Botan_bignum::Exp2>();
            break;
        case    CF_CALCOP("NumLSZeroBits(A)"):
            opRunner = std::make_unique<Botan_bignum::NumLSZeroBits>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            if ( op.modulo == std::nullopt ) {
                opRunner = std::make_unique<Botan_bignum::Sqrt>();
            } else {
                opRunner = std::make_unique<Botan_bignum::Ressol>();
            }
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
        /*
        case    CF_CALCOP("Ressol(A,B)"):
            opRunner = std::make_unique<Botan_bignum::Ressol>();
            break;
        */
        case    CF_CALCOP("Not(A)"):
            opRunner = std::make_unique<Botan_bignum::Not>();
            break;
        case    CF_CALCOP("Prime()"):
            opRunner = std::make_unique<Botan_bignum::Prime>();
            break;
        case    CF_CALCOP("RandRange(A,B)"):
            opRunner = std::make_unique<Botan_bignum::RandRange>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);

#if defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
    try {
#endif
        CF_CHECK_EQ(opRunner->Run(
                    ds,
                    res,
                    bn,
                    op.modulo ?
                        std::optional<Botan_bignum::Bignum>(Botan_bignum::Bignum(op.modulo->ToTrimmedString())) :
                        std::nullopt), true);
#if defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
    } catch ( ... ) {
        goto end;
    }
#endif

    ret = { util::HexToDec(res.Ref().to_hex_string()) };

end:
    return ret;
}

bool Botan::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
