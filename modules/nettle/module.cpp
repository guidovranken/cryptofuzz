#include "module.h"
#include <cryptofuzz/util.h>
#include <nettle/arcfour.h>
#include <nettle/ccm.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/chacha.h>
#include <nettle/cmac.h>
#include <nettle/eax.h>
#include <nettle/gcm.h>
#include <nettle/gosthash94.h>
#include <nettle/hkdf.h>
#include <nettle/hmac.h>
#include <nettle/md2.h>
#include <nettle/md4.h>
#include <nettle/md5.h>
#include <nettle/pbkdf2.h>
#include <nettle/ripemd160.h>
#include <nettle/sha.h>
#include <nettle/sha3.h>
#include <nettle/streebog.h>
#include <nettle/xts.h>

namespace cryptofuzz {
namespace module {

Nettle::Nettle(void) :
    Module("Nettle") { }

namespace Nettle_detail {
    template <class OperationType, class ReturnType, class CTXType>
    class Operation {
        protected:
            CTXType ctx;
        public:
            Operation(void) { }
            ~Operation() { }
            virtual bool runInit(OperationType& op) = 0;
            virtual void runUpdate(util::Multipart& parts) = 0;
            virtual std::vector<uint8_t> runFinalize(void) = 0;
            std::optional<ReturnType> Run(OperationType& op) {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                util::Multipart parts;

                if ( runInit(op) == false ) {
                    return std::nullopt;
                }

                parts = util::ToParts(ds, op.cleartext);

                runUpdate(parts);

                {
                    const auto ret = runFinalize();
                    return ReturnType(ret.data(), ret.size());
                }
            }
    };

    template <class CTXType, size_t DigestSize>
    class Digest : public Operation<operation::Digest, component::Digest, CTXType> {
        private:
            void (*init)(CTXType*);
            void (*update)(CTXType*, size_t, const uint8_t*);
            void (*digest)(CTXType*, size_t, uint8_t*);
        public:
            Digest(
                void (*init)(CTXType*),
                void (*update)(CTXType*, size_t, const uint8_t*),
                void (*digest)(CTXType*, size_t, uint8_t*)
            ) :
                Operation<operation::Digest, component::Digest, CTXType>(),
                init(init),
                update(update),
                digest(digest)
            { }

            bool runInit(operation::Digest& op) override {
                (void)op;
                /* noret */ init(&this->ctx);
                return true;
            }

            void runUpdate(util::Multipart& parts) override {
                for (const auto& part : parts) {
                    /* noret */ update(&this->ctx, part.second, part.first);
                }
            }

            std::vector<uint8_t> runFinalize(void) override {
                std::vector<uint8_t> ret(DigestSize);
                /* noret */ digest(&this->ctx, DigestSize, ret.data());
                return ret;
            }
    };

    template <class CTXType, size_t DigestSize>
    class HMAC : public Operation<operation::HMAC, component::MAC, CTXType> {
        private:
            void (*set_key)(CTXType*, size_t, const uint8_t*);
            void (*update)(CTXType*, size_t, const uint8_t*);
            void (*digest)(CTXType*, size_t, uint8_t*);
        public:
            HMAC(
                void (*set_key)(CTXType*, size_t, const uint8_t*),
                void (*update)(CTXType*, size_t, const uint8_t*),
                void (*digest)(CTXType*, size_t, uint8_t*)
            ) :
                Operation<operation::HMAC, component::MAC, CTXType>(),
                set_key(set_key),
                update(update),
                digest(digest)
            { }

            bool runInit(operation::HMAC& op) override {
                /* noret */ set_key(&this->ctx, op.cipher.key.GetSize(), op.cipher.key.GetPtr());
                return true;
            }

            void runUpdate(util::Multipart& parts) override {
                for (const auto& part : parts) {
                    /* noret */ update(&this->ctx, part.second, part.first);
                }
            }

            std::vector<uint8_t> runFinalize(void) override {
                std::vector<uint8_t> ret(DigestSize);
                /* noret */ digest(&this->ctx, DigestSize, ret.data());
                return ret;
            }
    };

    template <class CTXType, size_t DigestSize, size_t KeySize>
    class CMAC : public Operation<operation::CMAC, component::MAC, CTXType> {
        private:
            void (*set_key)(CTXType*, const uint8_t*);
            void (*update)(CTXType*, size_t, const uint8_t*);
            void (*digest)(CTXType*, size_t, uint8_t*);
        public:
            CMAC(
                void (*set_key)(CTXType*, const uint8_t*),
                void (*update)(CTXType*, size_t, const uint8_t*),
                void (*digest)(CTXType*, size_t, uint8_t*)
            ) :
                Operation<operation::CMAC, component::MAC, CTXType>(),
                set_key(set_key),
                update(update),
                digest(digest)
            { }

            bool runInit(operation::CMAC& op) override {
                bool ret = false;

                CF_CHECK_EQ(op.cipher.key.GetSize(), KeySize);

                /* noret */ set_key(&this->ctx, op.cipher.key.GetPtr());

                ret = true;

end:
                return ret;
            }

            void runUpdate(util::Multipart& parts) override {
                for (const auto& part : parts) {
                    /* noret */ update(&this->ctx, part.second, part.first);
                }
            }

            std::vector<uint8_t> runFinalize(void) override {
                std::vector<uint8_t> ret(DigestSize);
                /* noret */ digest(&this->ctx, DigestSize, ret.data());
                return ret;
            }
    };

    Digest<md2_ctx, MD2_DIGEST_SIZE> md2(md2_init, md2_update, md2_digest);
    Digest<md4_ctx, MD4_DIGEST_SIZE> md4(md4_init, md4_update, md4_digest);
    Digest<md5_ctx, MD5_DIGEST_SIZE> md5(md5_init, md5_update, md5_digest);
    Digest<ripemd160_ctx, RIPEMD160_DIGEST_SIZE> ripemd160(ripemd160_init, ripemd160_update, ripemd160_digest);
    Digest<sha1_ctx, SHA1_DIGEST_SIZE> sha1(sha1_init, sha1_update, sha1_digest);
    Digest<sha224_ctx, SHA224_DIGEST_SIZE> sha224(sha224_init, sha224_update, sha224_digest);
    Digest<sha256_ctx, SHA256_DIGEST_SIZE> sha256(sha256_init, sha256_update, sha256_digest);
    Digest<sha384_ctx, SHA384_DIGEST_SIZE> sha384(sha384_init, sha384_update, sha384_digest);
    Digest<sha512_ctx, SHA512_DIGEST_SIZE> sha512(sha512_init, sha512_update, sha512_digest);
    Digest<sha512_224_ctx, SHA512_224_DIGEST_SIZE> sha512_224(sha512_224_init, sha512_224_update, sha512_224_digest);
    Digest<sha512_256_ctx, SHA512_256_DIGEST_SIZE> sha512_256(sha512_256_init, sha512_256_update, sha512_256_digest);
    Digest<gosthash94_ctx, GOSTHASH94_DIGEST_SIZE> gosthash94(gosthash94_init, gosthash94_update, gosthash94_digest);
    Digest<sha3_224_ctx, SHA3_224_DIGEST_SIZE> sha3_224(sha3_224_init, sha3_224_update, sha3_224_digest);
    Digest<sha3_256_ctx, SHA3_256_DIGEST_SIZE> sha3_256(sha3_256_init, sha3_256_update, sha3_256_digest);
    Digest<sha3_384_ctx, SHA3_384_DIGEST_SIZE> sha3_384(sha3_384_init, sha3_384_update, sha3_384_digest);
    Digest<sha3_512_ctx, SHA3_512_DIGEST_SIZE> sha3_512(sha3_512_init, sha3_512_update, sha3_512_digest);
    Digest<streebog256_ctx, STREEBOG256_DIGEST_SIZE> streebog_256(streebog256_init, streebog256_update, streebog256_digest);
    Digest<streebog512_ctx, STREEBOG512_DIGEST_SIZE> streebog_512(streebog512_init, streebog512_update, streebog512_digest);

    HMAC<hmac_md5_ctx, MD5_DIGEST_SIZE> hmac_md5(hmac_md5_set_key, hmac_md5_update, hmac_md5_digest);
    HMAC<hmac_ripemd160_ctx, RIPEMD160_DIGEST_SIZE> hmac_ripemd160(hmac_ripemd160_set_key, hmac_ripemd160_update, hmac_ripemd160_digest);
    HMAC<hmac_sha1_ctx, SHA1_DIGEST_SIZE> hmac_sha1(hmac_sha1_set_key, hmac_sha1_update, hmac_sha1_digest);
    HMAC<hmac_sha224_ctx, SHA224_DIGEST_SIZE> hmac_sha224(hmac_sha224_set_key, hmac_sha224_update, hmac_sha224_digest);
    HMAC<hmac_sha256_ctx, SHA256_DIGEST_SIZE> hmac_sha256(hmac_sha256_set_key, hmac_sha256_update, hmac_sha256_digest);
    HMAC<hmac_sha512_ctx, SHA512_DIGEST_SIZE> hmac_sha512(hmac_sha512_set_key, hmac_sha512_update, hmac_sha512_digest);
    HMAC<hmac_streebog256_ctx, SHA256_DIGEST_SIZE> hmac_streebog256(hmac_streebog256_set_key, hmac_streebog256_update, hmac_streebog256_digest);
    HMAC<hmac_streebog512_ctx, SHA512_DIGEST_SIZE> hmac_streebog512(hmac_streebog512_set_key, hmac_streebog512_update, hmac_streebog512_digest);

    CMAC<cmac_aes128_ctx, CMAC128_DIGEST_SIZE, 16> cmac_aes128(cmac_aes128_set_key, cmac_aes128_update, cmac_aes128_digest);
    CMAC<cmac_aes256_ctx, CMAC128_DIGEST_SIZE, 32> cmac_aes256(cmac_aes256_set_key, cmac_aes256_update, cmac_aes256_digest);

} /* namespace Nettle_detail */

std::optional<component::Digest> Nettle::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("MD2"):
            ret = Nettle_detail::md2.Run(op);
            break;
        case CF_DIGEST("MD4"):
            ret = Nettle_detail::md4.Run(op);
            break;
        case CF_DIGEST("MD5"):
            ret = Nettle_detail::md5.Run(op);
            break;
        case CF_DIGEST("RIPEMD160"):
            ret = Nettle_detail::ripemd160.Run(op);
            break;
        case CF_DIGEST("SHA1"):
            ret = Nettle_detail::sha1.Run(op);
            break;
        case CF_DIGEST("SHA224"):
            ret = Nettle_detail::sha224.Run(op);
            break;
        case CF_DIGEST("SHA256"):
            ret = Nettle_detail::sha256.Run(op);
            break;
        case CF_DIGEST("SHA384"):
            ret = Nettle_detail::sha384.Run(op);
            break;
        case CF_DIGEST("SHA512"):
            ret = Nettle_detail::sha512.Run(op);
            break;
        case CF_DIGEST("SHA512-224"):
            ret = Nettle_detail::sha512_224.Run(op);
            break;
        case CF_DIGEST("SHA512-256"):
            ret = Nettle_detail::sha512_256.Run(op);
            break;
        case CF_DIGEST("SHA3-224"):
            ret = Nettle_detail::sha3_224.Run(op);
            break;
        case CF_DIGEST("SHA3-256"):
            ret = Nettle_detail::sha3_256.Run(op);
            break;
        case CF_DIGEST("SHA3-384"):
            ret = Nettle_detail::sha3_384.Run(op);
            break;
        case CF_DIGEST("SHA3-512"):
            ret = Nettle_detail::sha3_512.Run(op);
            break;
        case CF_DIGEST("GOST-R-34.11-94-NO-CRYPTOPRO"):
            ret = Nettle_detail::gosthash94.Run(op);
            break;
        case CF_DIGEST("STREEBOG-256"):
            ret = Nettle_detail::streebog_256.Run(op);
            break;
        case CF_DIGEST("STREEBOG-512"):
            ret = Nettle_detail::streebog_512.Run(op);
            break;
    }

    return ret;
}

std::optional<component::MAC> Nettle::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("MD5"):
            ret = Nettle_detail::hmac_md5.Run(op);
            break;
        case CF_DIGEST("RIPEMD160"):
            ret = Nettle_detail::hmac_ripemd160.Run(op);
            break;
        case CF_DIGEST("SHA1"):
            ret = Nettle_detail::hmac_sha1.Run(op);
            break;
        case CF_DIGEST("SHA256"):
            ret = Nettle_detail::hmac_sha256.Run(op);
            break;
        case CF_DIGEST("SHA512"):
            ret = Nettle_detail::hmac_sha512.Run(op);
            break;
        case CF_DIGEST("STREEBOG-256"):
            ret = Nettle_detail::hmac_streebog256.Run(op);
            break;
        case CF_DIGEST("STREEBOG-512"):
            ret = Nettle_detail::hmac_streebog512.Run(op);
            break;
    }

    return ret;
}

std::optional<component::MAC> Nettle::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
            ret = Nettle_detail::cmac_aes128.Run(op);
            break;
        case CF_CIPHER("AES_256_CBC"):
            ret = Nettle_detail::cmac_aes256.Run(op);
            break;
    }

    return ret;
}

std::optional<component::Ciphertext> Nettle::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    uint8_t* out = nullptr;
    uint8_t* outTag = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_GCM"):
        {
            struct gcm_aes128_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_LTE(*op.tagSize, GCM_DIGEST_SIZE);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ gcm_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ gcm_aes128_set_iv(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ gcm_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ gcm_aes128_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ gcm_aes128_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_256_GCM"):
        {
            struct gcm_aes256_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_LTE(*op.tagSize, GCM_DIGEST_SIZE);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ gcm_aes256_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ gcm_aes256_set_iv(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ gcm_aes256_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ gcm_aes256_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ gcm_aes256_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_128_EAX"):
        {
            struct eax_aes128_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_LTE(*op.tagSize, EAX_DIGEST_SIZE);
            CF_CHECK_GT(*op.tagSize, 0); /* XXX crashes without this check. This is probably a bug in Nettle */

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ eax_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ eax_aes128_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ eax_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ eax_aes128_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ eax_aes128_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_128_CCM"):
        {
            struct ccm_aes128_ctx ctx;

            CF_CHECK_GTE(op.cipher.iv.GetSize(), 7);
            CF_CHECK_LTE(op.cipher.iv.GetSize(), 13);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            {
                static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};
                if ( std::find(validTagSizes.begin(), validTagSizes.end(), *op.tagSize) == validTagSizes.end() ) {
                    goto end;
                }
            }

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ ccm_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ ccm_aes128_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr(), op.aad == std::nullopt ? 0 : op.aad->GetSize(), op.cleartext.GetSize(), *op.tagSize);
            if ( op.aad != std::nullopt ) {
                /* noret */ ccm_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ ccm_aes128_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ ccm_aes128_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_256_CCM"):
        {
            struct ccm_aes256_ctx ctx;

            CF_CHECK_GTE(op.cipher.iv.GetSize(), 7);
            CF_CHECK_LTE(op.cipher.iv.GetSize(), 13);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            {
                static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};
                if ( std::find(validTagSizes.begin(), validTagSizes.end(), *op.tagSize) == validTagSizes.end() ) {
                    goto end;
                }
            }

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ ccm_aes256_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ ccm_aes256_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr(), op.aad == std::nullopt ? 0 : op.aad->GetSize(), op.cleartext.GetSize(), *op.tagSize);
            if ( op.aad != std::nullopt ) {
                /* noret */ ccm_aes256_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ ccm_aes256_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ ccm_aes256_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;


        case CF_CIPHER("CHACHA20"):
        {
            struct chacha_ctx ctx;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_NONCE_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA_KEY_SIZE);
            out = util::malloc(op.cleartext.GetSize());

            /* noret */ chacha_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ chacha_set_nonce(&ctx, op.cipher.iv.GetPtr());
            /* noret */ chacha_crypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20_POLY1305"):
        {
            struct chacha_poly1305_ctx ctx;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_POLY1305_NONCE_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA_POLY1305_KEY_SIZE);
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_LTE(*op.tagSize, CHACHA_POLY1305_DIGEST_SIZE);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            /* noret */ chacha_poly1305_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ chacha_poly1305_set_nonce(&ctx, op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ chacha_poly1305_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ chacha_poly1305_encrypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());
            /* noret */ chacha_poly1305_digest(&ctx, *op.tagSize, outTag);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_128_XTS"):
        {
            struct xts_aes128_key ctx;
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_GT(op.cleartext.GetSize(), 0);
            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), XTS_BLOCK_SIZE);

            out = util::malloc(op.cleartext.GetSize());

            /* noret */ xts_aes128_set_encrypt_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ xts_aes128_encrypt_message(&ctx, op.cipher.iv.GetPtr(), op.cleartext.GetSize(), out, op.cleartext.GetPtr());

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_256_XTS"):
        {
            struct xts_aes256_key ctx;
            CF_CHECK_EQ(op.cipher.key.GetSize(), 512 / 8);
            CF_CHECK_GT(op.cleartext.GetSize(), 0);
            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), XTS_BLOCK_SIZE);

            out = util::malloc(op.cleartext.GetSize());

            /* noret */ xts_aes256_set_encrypt_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ xts_aes256_encrypt_message(&ctx, op.cipher.iv.GetPtr(), op.cleartext.GetSize(), out, op.cleartext.GetPtr());

            if ( op.cleartext.GetSize() ) out[0]++;
            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            struct arcfour_ctx ctx;

            CF_CHECK_GTE(op.cipher.key.GetSize(), ARCFOUR_MIN_KEY_SIZE);
            CF_CHECK_LTE(op.cipher.key.GetSize(), ARCFOUR_MAX_KEY_SIZE);

            out = util::malloc(op.cleartext.GetSize());

            /* noret */ arcfour_set_key(&ctx, op.cipher.key.GetSize(), op.cipher.key.GetPtr());
            /* noret */ arcfour_crypt(&ctx, op.cleartext.GetSize(), out, op.cleartext.GetPtr());

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;
    }

end:
    util::free(out);
    util::free(outTag);

    return ret;
}


std::optional<component::Cleartext> Nettle::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    uint8_t* out = nullptr;
    uint8_t* outTag = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_GCM"):
        {
            struct gcm_aes128_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_LTE(op.tag->GetSize(), GCM_DIGEST_SIZE);

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ gcm_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ gcm_aes128_set_iv(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ gcm_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ gcm_aes128_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ gcm_aes128_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_256_GCM"):
        {
            struct gcm_aes256_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_LTE(op.tag->GetSize(), GCM_DIGEST_SIZE);

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ gcm_aes256_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ gcm_aes256_set_iv(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ gcm_aes256_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ gcm_aes256_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ gcm_aes256_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_EAX"):
        {
            struct eax_aes128_ctx ctx;

            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_LTE(op.tag->GetSize(), EAX_DIGEST_SIZE);
            CF_CHECK_GT(op.tag->GetSize(), 0); /* XXX crashes without this check. This is probably a bug in Nettle */

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ eax_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ eax_aes128_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ eax_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ eax_aes128_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ eax_aes128_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CCM"):
        {
            struct ccm_aes128_ctx ctx;

            CF_CHECK_GTE(op.cipher.iv.GetSize(), 7);
            CF_CHECK_LTE(op.cipher.iv.GetSize(), 13);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 128 / 8);
            CF_CHECK_NE(op.tag, std::nullopt);
            {
                static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};
                if ( std::find(validTagSizes.begin(), validTagSizes.end(), op.tag->GetSize()) == validTagSizes.end() ) {
                    goto end;
                }
            }

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ ccm_aes128_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ ccm_aes128_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr(), op.aad == std::nullopt ? 0 : op.aad->GetSize(), op.ciphertext.GetSize(), op.tag->GetSize());
            if ( op.aad != std::nullopt ) {
                /* noret */ ccm_aes128_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ ccm_aes128_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ ccm_aes128_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_256_CCM"):
        {
            struct ccm_aes256_ctx ctx;

            CF_CHECK_GTE(op.cipher.iv.GetSize(), 7);
            CF_CHECK_LTE(op.cipher.iv.GetSize(), 13);
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_NE(op.tag, std::nullopt);
            {
                static const std::vector<size_t> validTagSizes = {4, 6, 8, 10, 12, 14, 16};
                if ( std::find(validTagSizes.begin(), validTagSizes.end(), op.tag->GetSize()) == validTagSizes.end() ) {
                    goto end;
                }
            }

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ ccm_aes256_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ ccm_aes256_set_nonce(&ctx, op.cipher.iv.GetSize(), op.cipher.iv.GetPtr(), op.aad == std::nullopt ? 0 : op.aad->GetSize(), op.ciphertext.GetSize(), op.tag->GetSize());
            if ( op.aad != std::nullopt ) {
                /* noret */ ccm_aes256_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ ccm_aes256_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ ccm_aes256_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20"):
        {
            struct chacha_ctx ctx;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_NONCE_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA_KEY_SIZE);
            out = util::malloc(op.ciphertext.GetSize());

            /* noret */ chacha_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ chacha_set_nonce(&ctx, op.cipher.iv.GetPtr());
            /* noret */ chacha_crypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20_POLY1305"):
        {
            struct chacha_poly1305_ctx ctx;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_POLY1305_NONCE_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA_POLY1305_KEY_SIZE);
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_LTE(op.tag->GetSize(), CHACHA_POLY1305_DIGEST_SIZE);

            out = util::malloc(op.ciphertext.GetSize());
            outTag = util::malloc(op.tag->GetSize());

            /* noret */ chacha_poly1305_set_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ chacha_poly1305_set_nonce(&ctx, op.cipher.iv.GetPtr());
            if ( op.aad != std::nullopt ) {
                /* noret */ chacha_poly1305_update(&ctx, op.aad->GetSize(), op.aad->GetPtr());
            }
            /* noret */ chacha_poly1305_decrypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());
            /* noret */ chacha_poly1305_digest(&ctx, op.tag->GetSize(), outTag);

            CF_CHECK_EQ(memcmp(op.tag->GetPtr(), outTag, op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_XTS"):
        {
            struct xts_aes128_key ctx;
            CF_CHECK_EQ(op.cipher.key.GetSize(), 256 / 8);
            CF_CHECK_GT(op.ciphertext.GetSize(), 0);
            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), XTS_BLOCK_SIZE);

            out = util::malloc(op.ciphertext.GetSize());

            /* noret */ xts_aes128_set_decrypt_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ xts_aes128_decrypt_message(&ctx, op.cipher.iv.GetPtr(), op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_256_XTS"):
        {
            struct xts_aes256_key ctx;
            CF_CHECK_EQ(op.cipher.key.GetSize(), 512 / 8);
            CF_CHECK_GT(op.ciphertext.GetSize(), 0);
            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), XTS_BLOCK_SIZE);

            out = util::malloc(op.ciphertext.GetSize());

            /* noret */ xts_aes256_set_decrypt_key(&ctx, op.cipher.key.GetPtr());
            /* noret */ xts_aes256_decrypt_message(&ctx, op.cipher.iv.GetPtr(), op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            struct arcfour_ctx ctx;

            CF_CHECK_GTE(op.cipher.key.GetSize(), ARCFOUR_MIN_KEY_SIZE);
            CF_CHECK_LTE(op.cipher.key.GetSize(), ARCFOUR_MAX_KEY_SIZE);

            out = util::malloc(op.ciphertext.GetSize());

            /* noret */ arcfour_set_key(&ctx, op.cipher.key.GetSize(), op.cipher.key.GetPtr());
            /* noret */ arcfour_crypt(&ctx, op.ciphertext.GetSize(), out, op.ciphertext.GetPtr());

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;
    }

end:
    util::free(out);
    util::free(outTag);

    return ret;
}

std::optional<component::Key> Nettle::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            {
                struct hmac_sha1_ctx ctx;
                uint8_t prk[SHA1_DIGEST_SIZE];

                CF_CHECK_LTE(op.keySize, 255 * SHA1_DIGEST_SIZE);

                hmac_sha1_set_key(&ctx, op.salt.GetSize(), op.salt.GetPtr());
                hkdf_extract(&ctx,
                        (nettle_hash_update_func*) hmac_sha1_update,
                        (nettle_hash_digest_func*) hmac_sha1_digest,
                        SHA1_DIGEST_SIZE,
                        op.password.GetSize(), op.password.GetPtr(), prk);
                hmac_sha1_set_key(&ctx, SHA1_DIGEST_SIZE, prk);
                hkdf_expand(&ctx,
                        (nettle_hash_update_func*) hmac_sha1_update,
                        (nettle_hash_digest_func*) hmac_sha1_digest,
                        SHA1_DIGEST_SIZE,
                        op.info.GetSize(),
                        op.info.GetPtr(),
                        op.keySize,
                        out);
                ret = component::Key(out, op.keySize);
            }
            break;
        case CF_DIGEST("SHA256"):
            {
                struct hmac_sha256_ctx ctx;
                uint8_t prk[SHA256_DIGEST_SIZE];

                CF_CHECK_LTE(op.keySize, 255 * SHA256_DIGEST_SIZE);

                hmac_sha256_set_key(&ctx, op.salt.GetSize(), op.salt.GetPtr());
                hkdf_extract(&ctx,
                        (nettle_hash_update_func*) hmac_sha256_update,
                        (nettle_hash_digest_func*) hmac_sha256_digest,
                        SHA256_DIGEST_SIZE,
                        op.password.GetSize(), op.password.GetPtr(), prk);
                hmac_sha256_set_key(&ctx, SHA256_DIGEST_SIZE, prk);
                hkdf_expand(&ctx,
                        (nettle_hash_update_func*) hmac_sha256_update,
                        (nettle_hash_digest_func*) hmac_sha256_digest,
                        SHA256_DIGEST_SIZE,
                        op.info.GetSize(),
                        op.info.GetPtr(),
                        op.keySize,
                        out);
                ret = component::Key(out, op.keySize);
            }
            break;
    }

end:

    util::free(out);

    return ret;
}

std::optional<component::Key> Nettle::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_GT(op.iterations, 0);

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            {
                /* noret */ pbkdf2_hmac_sha1(op.password.GetSize(), op.password.GetPtr(), op.iterations, op.salt.GetSize(), op.salt.GetPtr(), op.keySize, out);
                ret = component::Key(out, op.keySize);
            }
            break;
        case CF_DIGEST("SHA256"):
            {
                /* noret */ pbkdf2_hmac_sha256(op.password.GetSize(), op.password.GetPtr(), op.iterations, op.salt.GetSize(), op.salt.GetPtr(), op.keySize, out);
                ret = component::Key(out, op.keySize);
            }
            break;
    }

end:
    util::free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
