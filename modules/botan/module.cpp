#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/cmac.h>
#include <botan/cipher_mode.h>
#include <botan/pbkdf.h>
#include <botan/pwdhash.h>
#include <botan/kdf.h>
#include <botan/system_rng.h>
#include <botan/bigint.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/ber_dec.h>
#include "bn_ops.h"

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
            CF_CHECK_NE(algoString = Botan_detail::DigestIDToString(op.digestType.Get(), true, true), std::nullopt);

            const bool isSipHash = op.digestType.Get() == CF_DIGEST("SIPHASH64");

            const std::string hmacString = isSipHash ? *algoString : Botan_detail::parenthesize("HMAC", *algoString);
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

std::optional<component::MAC> Botan::OpCMAC(operation::CMAC& op) {
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
}

std::optional<component::Ciphertext> Botan::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    return Botan_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt>(op);
}

std::optional<component::Cleartext> Botan::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    return Botan_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt>(op);
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

            /* Workaround for an anomaly in Botan: https://github.com/randombit/botan/issues/2347 */
            CF_CHECK_GTE(derived.size(), op.keySize);

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

std::optional<component::ECC_PublicKey> Botan::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    static ::Botan::System_RNG rng;
    try {
        std::optional<std::string> curveString;
        CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
        ::Botan::EC_Group group(*curveString);

        const ::Botan::BigInt priv_bn(op.priv.ToString(ds));
        auto priv = std::make_unique<::Botan::ECDSA_PrivateKey>(::Botan::ECDSA_PrivateKey(rng, group, priv_bn));

        const auto pub_x = priv->public_point().get_affine_x();
        const auto pub_y = priv->public_point().get_affine_y();

        ret = { pub_x.to_dec_string(), pub_y.to_dec_string() };
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

    static ::Botan::System_RNG rng;

    try {
        /* Initialize */
        {
            std::optional<std::string> curveString;
            CF_CHECK_NE(curveString = Botan_detail::CurveIDToString(op.curveType.Get()), std::nullopt);
            ::Botan::EC_Group group(*curveString);

            /* TODO check hash algorithm */

            /* Private key */
            {
                const ::Botan::BigInt priv_bn(op.priv.ToString(ds));
                priv = std::make_unique<::Botan::ECDSA_PrivateKey>(::Botan::ECDSA_PrivateKey(rng, group, priv_bn));
            }

            /* Prepare signer */
            signer.reset(new ::Botan::PK_Signer(*priv, rng, "EMSA1(SHA-1)", ::Botan::DER_SEQUENCE));
        }

        /* Process */
        {
            const auto signature = signer->sign_message(op.cleartext.Get(), rng);

            /* Retrieve R and S */
            {
                ::Botan::BER_Decoder decoder(signature);
                ::Botan::BER_Decoder ber_sig = decoder.start_cons(::Botan::SEQUENCE);

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

                const auto R_str = R.to_dec_string();
                const auto S_str = S.to_dec_string();

                ret = { R_str, S_str };
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
            const ::Botan::BigInt pub_x(op.pub.first.ToString(ds));
            const ::Botan::BigInt pub_y(op.pub.second.ToString(ds));
            const ::Botan::PointGFp public_point = group.point(pub_x, pub_y);
            pub = std::make_unique<::Botan::ECDSA_PublicKey>(::Botan::ECDSA_PublicKey(group, public_point));
        }

        ::Botan::PK_Verifier verifier(*pub, "Raw");

        const ::Botan::BigInt R(op.signature.first.ToString(ds));
        const ::Botan::BigInt S(op.signature.second.ToString(ds));

        /* XXX may throw: Encoding error: encode_fixed_length_int_pair: values too large to encode properly */
        auto sig = ::Botan::BigInt::encode_fixed_length_int_pair(R, S, group.get_order_bytes());

        ret = verifier.verify_message(op.cleartext.Get(), sig);
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
    }

    CF_CHECK_NE(opRunner, nullptr);

    try {
        CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);
    } catch ( ... ) {
        goto end;
    }

    ret = { res.is_negative() ?
            ("-" + res.to_dec_string()) :
            res.to_dec_string() };

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
