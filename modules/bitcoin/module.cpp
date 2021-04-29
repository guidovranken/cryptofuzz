#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <memory>

#include "crypto/sha1.cpp"
#include "crypto/sha256.cpp"
#include "crypto/sha512.cpp"
#include "crypto/sha3.cpp"
#include "crypto/ripemd160.cpp"

#include "crypto/hmac_sha256.cpp"
#include "crypto/hmac_sha512.cpp"

#include "crypto/hkdf_sha256_32.cpp"

#include "crypto/aes.cpp"
#include "crypto/chacha20.cpp"
#include "crypto/poly1305.cpp"
#include "crypto/chacha_poly_aead.cpp"

#include "crypto/siphash.cpp"

#include "uint256.cpp"
#include "arith_uint256.cpp"

#include "cleanse.cpp"
#include "util/strencodings.cpp"

namespace cryptofuzz {
namespace module {

Bitcoin::Bitcoin(void) :
    Module("Bitcoin") { }

namespace Bitcoin_detail {

template <class Alg>
void digest_write(std::shared_ptr<Alg> alg, const uint8_t* data, const size_t size) {
    alg->Write(data, size);
}

template <>
void digest_write(std::shared_ptr<SHA3_256> alg, const uint8_t* data, const size_t size) {
    alg->Write({data, size});
}

template <class Alg>
std::optional<component::Digest> digest(operation::Digest& op, Datasource& ds) {
    std::optional<component::Digest> ret = std::nullopt;

    size_t numResets = 0;
    util::Multipart parts;
    std::shared_ptr<Alg> alg = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        alg = std::make_shared<Alg>();
    }

again:

    /* Process */
    for (const auto& part : parts) {
        digest_write(alg, part.first, part.second);
        try {
            if ( numResets < 5 && ds.Get<bool>() ) {
                alg->Reset();
                numResets++;
                goto again;
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }
    }

    /* Finalize */
    {
        uint8_t out[Alg::OUTPUT_SIZE];
        alg->Finalize(out);
        ret = component::Digest(out, Alg::OUTPUT_SIZE);
    }

    return ret;
}

} /* namespace Bitcoin_detail */

std::optional<component::Digest> Bitcoin::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            return Bitcoin_detail::digest<CSHA1>(op, ds);
        case CF_DIGEST("SHA256"):
            return Bitcoin_detail::digest<CSHA256>(op, ds);
        case CF_DIGEST("SHA512"):
            return Bitcoin_detail::digest<CSHA512>(op, ds);
        case CF_DIGEST("RIPEMD160"):
            return Bitcoin_detail::digest<CRIPEMD160>(op, ds);
        case CF_DIGEST("SHA3-256"):
            return Bitcoin_detail::digest<SHA3_256>(op, ds);
    }

    return ret;
}

namespace Bitcoin_detail {

template <class Alg>
std::optional<component::MAC> hmac(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;
    std::unique_ptr<Alg> alg = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        alg = std::make_unique<Alg>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
    }

    /* Process */
    for (const auto& part : parts) {
        alg->Write(part.first, part.second);
    }

    /* Finalize */
    {
        uint8_t out[Alg::OUTPUT_SIZE];
        alg->Finalize(out);
        ret = component::MAC(out, Alg::OUTPUT_SIZE);
    }

    return ret;
}

} /* namespace Bitcoin_detail */

namespace Bitcoin_detail {
    static std::optional<component::Digest> SipHash64(operation::HMAC& op, Datasource& ds) {
        std::optional<component::Digest> ret = std::nullopt;

        util::Multipart parts;
        std::unique_ptr<CSipHasher> alg = nullptr;

        /* Initialize */
        {
            if ( op.cipher.key.GetSize() != 16 ) {
                return ret;
            }

            uint64_t key[2];
            memcpy(&key[0], op.cipher.key.GetPtr(), 8);
            memcpy(&key[1], op.cipher.key.GetPtr() + 8, 8);

            if ( op.cleartext.GetSize() == 32 || op.cleartext.GetSize() == 36 ) {
                bool oneShot = false;
                try {
                    oneShot = ds.Get<bool>();
                } catch ( ... ) { }

                if ( oneShot == true ) {
                    uint64_t out;

                    if ( op.cleartext.GetSize() == 32 ) {
                        out = SipHashUint256(key[0], key[1], uint256(op.cleartext.Get()));
                    } else if ( op.cleartext.GetSize() == 36 ) {
                        uint8_t in[32];
                        uint32_t extra;

                        memcpy(in, op.cleartext.GetPtr(), sizeof(in));
                        memcpy(&extra, op.cleartext.GetPtr() + 32, sizeof(extra));

                        out = SipHashUint256Extra(
                                key[0],
                                key[1],
                                uint256(std::vector<uint8_t>(in, in + sizeof(in))),
                                extra);
                    } else {
                        abort();
                    }

                    ret = component::Digest((const uint8_t*)&out, sizeof(out));

                    return ret;
                }
            }

            alg = std::make_unique<CSipHasher>(key[0], key[1]);

            //if ( op.cleartext.GetSize() > 0 && (op.cleartext.GetSize() % 8) == 0 && ds.Get<bool>() == true ) {
            if ( (op.cleartext.GetSize() % 8) == 0 && ds.Get<bool>() == true ) {
                for (size_t i = 0; i < op.cleartext.GetSize(); i += 8) {
                    uint64_t v;
                    memcpy(&v, op.cleartext.GetPtr() + i, sizeof(v));
                    alg->Write(v);
                }

                const auto out = alg->Finalize();
                ret = component::Digest((const uint8_t*)&out, sizeof(out));

                return ret;
            }


            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        {
            for (const auto& part : parts) {
                alg->Write(part.first, part.second);
            }
        }

        /* Finalize */
        {
            const auto out = alg->Finalize();
            ret = component::Digest((const uint8_t*)&out, sizeof(out));
        }

        return ret;
    }
}

std::optional<component::MAC> Bitcoin::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return Bitcoin_detail::hmac<CHMAC_SHA256>(op, ds);
        case CF_DIGEST("SHA512"):
            return Bitcoin_detail::hmac<CHMAC_SHA512>(op, ds);
        case CF_DIGEST("SIPHASH64"):
            return Bitcoin_detail::SipHash64(op, ds);
    }

    return ret;
}

namespace Bitcoin_detail {
    template <class T>
    std::optional<T> chacha20(const Buffer& key, const Buffer& iv, const Buffer& in) {
        std::optional<T> ret = std::nullopt;

        if ( key.GetSize() != 16 && key.GetSize() != 32 ) {
            return ret;
        }
        if ( iv.GetSize() != 8 ) {
            return std::nullopt;
        }

        uint64_t iv_uint64_t;

        ChaCha20 cc20(key.GetPtr(), key.GetSize());

        memcpy(&iv_uint64_t, iv.GetPtr(), sizeof(iv_uint64_t));
        cc20.SetIV(iv_uint64_t);

        uint8_t* out = util::malloc(in.GetSize());

        CF_NORET(cc20.Crypt(in.GetPtr(), out, in.GetSize()));

        ret = T(Buffer(out, in.GetSize()));
        util::free(out);

        return ret;
    }

    std::optional<component::Ciphertext> chacha20_poly1305(const operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;

        if ( op.cipher.key.GetSize() != CHACHA20_POLY1305_AEAD_KEY_LEN ) {
            return ret;
        }

        if ( op.aad == std::nullopt || op.aad->GetSize() != CHACHA20_POLY1305_AEAD_KEY_LEN ) {
            return ret;
        }

        if ( op.tagSize == std::nullopt || *op.tagSize != POLY1305_TAGLEN ) {
            return ret;
        }

        if ( op.cipher.iv.GetSize() != 12 ) {
            return ret;
        }

        uint64_t seqnr_payload, seqnr_aad;
        memcpy(&seqnr_payload, op.cipher.iv.GetPtr(), sizeof(seqnr_payload));
        memcpy(&seqnr_aad, op.cipher.iv.GetPtr() + sizeof(seqnr_payload), sizeof(seqnr_aad));

        uint8_t* out = util::malloc(op.ciphertextSize);

        ChaCha20Poly1305AEAD aead(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.aad->GetPtr(), op.aad->GetSize());

        CF_CHECK_TRUE(aead.Crypt(seqnr_payload, seqnr_aad, 0, out, op.ciphertextSize, op.cleartext.GetPtr(), op.cleartext.GetSize(), true));

        CF_ASSERT(op.ciphertextSize >= op.cleartext.GetSize() + POLY1305_TAGLEN, "ChaCha20Poly1305AEAD succeeded with invalid output size");

        ret = component::Ciphertext(
                Buffer(out, op.cleartext.GetSize()),
                Buffer(out + op.cleartext.GetSize(), POLY1305_TAGLEN));

end:
        util::free(out);

        return ret;
    }

    std::optional<component::Cleartext> chacha20_poly1305(const operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;

        if ( op.cipher.key.GetSize() != CHACHA20_POLY1305_AEAD_KEY_LEN ) {
            return ret;
        }

        if ( op.aad == std::nullopt || op.aad->GetSize() != CHACHA20_POLY1305_AEAD_KEY_LEN ) {
            return ret;
        }

        if ( op.tag == std::nullopt || op.tag->GetSize() != POLY1305_TAGLEN ) {
            return ret;
        }

        if ( op.cipher.iv.GetSize() != 12 ) {
            return ret;
        }

        uint8_t* out = util::malloc(op.cleartextSize);

        ChaCha20Poly1305AEAD aead(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.aad->GetPtr(), op.aad->GetSize());

        const auto in = util::Append(op.ciphertext.Get(), op.tag->Get());
        CF_CHECK_TRUE(aead.Crypt(0, 0, 0, out, op.cleartextSize, in.data(), in.size(), false));

        CF_ASSERT(op.cleartextSize >= op.ciphertext.GetSize(), "ChaCha20Poly1305AEAD succeeded with invalid output size");

        ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));

end:
        util::free(out);

        return ret;
    }

    std::optional<component::Ciphertext> aes_256_cbc(const operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;

        std::unique_ptr<AES256CBCEncrypt> aes = nullptr;
        uint8_t* out = util::malloc(op.cleartext.GetSize() + AES_BLOCKSIZE);
        int numWritten;

        /* Initialize */
        {
            CF_CHECK_EQ(op.cipher.key.GetSize(), AES256_KEYSIZE);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), AES_BLOCKSIZE);
            aes = std::make_unique<AES256CBCEncrypt>(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), true);
        }

        /* Process */
        {
            CF_CHECK_GT(numWritten = aes->Encrypt(op.cleartext.GetPtr(), op.cleartext.GetSize(), out), 0);
        }

        /* Finalize */
        {
            ret = component::Ciphertext(Buffer(out, numWritten));
        }

end:
        util::free(out);

        return ret;
    }

    std::optional<component::Cleartext> aes_256_cbc(const operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;

        std::unique_ptr<AES256CBCDecrypt> aes = nullptr;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());
        int numWritten;

        /* Initialize */
        {
            CF_CHECK_EQ(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC"));
            CF_CHECK_EQ(op.cipher.key.GetSize(), AES256_KEYSIZE);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), AES_BLOCKSIZE);
            aes = std::make_unique<AES256CBCDecrypt>(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), true);
        }

        /* Process */
        {
            CF_CHECK_GT(numWritten = aes->Decrypt(op.ciphertext.GetPtr(), op.ciphertext.GetSize(), out), 0);
        }

        /* Finalize */
        {
            ret = component::Cleartext(out, numWritten);
        }

end:
        util::free(out);

        return ret;
    }

} /* namespace Bitcoin_detail */

std::optional<component::Ciphertext> Bitcoin::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20")) ) {
        return Bitcoin_detail::chacha20<component::Ciphertext>(op.cipher.key, op.cipher.iv, op.cleartext);
    } else if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) ) {
        return Bitcoin_detail::chacha20_poly1305(op);
    } else if ( op.cipher.cipherType.Is(CF_CIPHER("AES_256_CBC")) ) {
        return Bitcoin_detail::aes_256_cbc(op);
    }

    return std::nullopt;

}

std::optional<component::Cleartext> Bitcoin::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20")) ) {
        return Bitcoin_detail::chacha20<component::Cleartext>(op.cipher.key, op.cipher.iv, op.ciphertext);
    } else if ( op.cipher.cipherType.Is(CF_CIPHER("CHACHA20_POLY1305")) ) {
        return Bitcoin_detail::chacha20_poly1305(op);
    } else if ( op.cipher.cipherType.Is(CF_CIPHER("AES_256_CBC")) ) {
        return Bitcoin_detail::aes_256_cbc(op);
    }

    return std::nullopt;
}

std::optional<component::Key> Bitcoin::OpKDF_HKDF(operation::KDF_HKDF& op) {
    if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return std::nullopt;
    }

    if ( op.keySize != 32 ) {
        return std::nullopt;
    }

    if ( op.info.GetSize() > 128 ) {
        return std::nullopt;
    }

    uint8_t out[32];

    CHKDF_HMAC_SHA256_L32 hkdf(
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.AsString());

    CF_NORET(hkdf.Expand32(op.info.AsString(), out));

    return component::Key(out, sizeof(out));
}

namespace Bitcoin_detail {
    class Bignum {
        private:
            Datasource& ds;
            arith_uint256 bn;
        public:
            Bignum(Datasource& ds) :
                ds(ds) {
            }
            arith_uint256& Ref(void) {
                {
                    bool convert = false;
                    try {
                        convert = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                    if ( convert ) {
                        bn = UintToArith256(ArithToUint256(bn));
                    }
                }

                {
                    bool getDouble = false;
                    try {
                        getDouble = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                    if ( getDouble ) {
                        const auto d = bn.getdouble();
                        (void)d;
                    }
                }

                return bn;
            }
    };
}

namespace Bitcoin_detail {
    bool UseParamTwice(fuzzing::datasource::Datasource& ds, const arith_uint256& A, const arith_uint256& B) {
        if ( A != B ) {
            return false;
        }

        try {
            return ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return false;
    }

    uint8_t GetMod3(fuzzing::datasource::Datasource& ds) {
        try {
            return ds.Get<uint8_t>() % 3;
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return 0;
    }
} /* namespace Bitcoin_detail */


std::optional<component::Bignum> Bitcoin::OpBignumCalc(operation::BignumCalc& op) {
#define PREPARE_RESULT() {resultIdx = Bitcoin_detail::GetMod3(ds);}
#define RESULT_REF() (resultIdx == 0 ? result : (resultIdx == 1 ? &a : &b))
#define RESULT() ((resultIdx == 0 ? result : (resultIdx == 1 ? a : b)).Ref())
#define PARAM_B() ((Bitcoin_detail::UseParamTwice(ds, a.Ref(), b.Ref()) ? a : b).Ref())

    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    if ( op.modulo->ToTrimmedString() != "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Bignum> ret = std::nullopt;

    Bitcoin_detail::Bignum result(ds), a(ds), b(ds);

    a.Ref().SetHex(util::DecToHex(op.bn0.ToTrimmedString()));
    b.Ref().SetHex(util::DecToHex(op.bn1.ToTrimmedString()));

    uint8_t resultIdx;

    PREPARE_RESULT();

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            RESULT() = a.Ref() + PARAM_B();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            RESULT() = a.Ref() - PARAM_B();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            RESULT() = a.Ref() * PARAM_B();
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_NE(PARAM_B(), 0);
            RESULT() = a.Ref() / PARAM_B();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            RESULT() = a.Ref() == PARAM_B();
            break;
        case    CF_CALCOP("IsGt(A,B)"):
            RESULT() = a.Ref() > PARAM_B();
            break;
        case    CF_CALCOP("IsGte(A,B)"):
            RESULT() = a.Ref() >= PARAM_B();
            break;
        case    CF_CALCOP("IsLt(A,B)"):
            RESULT() = a.Ref() < PARAM_B();
            break;
        case    CF_CALCOP("IsLte(A,B)"):
            RESULT() = a.Ref() <= PARAM_B();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            RESULT() = a.Ref() & 1;
            break;
        case    CF_CALCOP("Set(A)"):
            RESULT() = a.Ref();
            break;
        case    CF_CALCOP("And(A,B)"):
            RESULT() = a.Ref() & PARAM_B();
            break;
        case    CF_CALCOP("Or(A,B)"):
            RESULT() = a.Ref() | PARAM_B();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            RESULT() = a.Ref() ^ PARAM_B();
            break;
        case    CF_CALCOP("NumBits(A)"):
            RESULT() = a.Ref().bits();
            break;
        default:
            goto end;
    }

    ret = util::HexToDec(RESULT().GetHex());

end:
    return ret;

#undef PREPARE_RESULT
#undef RESULT_PTR
#undef RESULT
#undef PARAM_B
}

bool Bitcoin::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
