#include "module.h"
#include <cryptofuzz/util.h>
#include <nettle/md2.h>
#include <nettle/md4.h>
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/sha.h>
#include <nettle/sha3.h>
#include <nettle/gosthash94.h>
#include <nettle/hmac.h>
#include <nettle/cmac.h>
#include <nettle/pbkdf2.h>

namespace cryptofuzz {
namespace module {

Nettle::Nettle(void) :
    Module("Nettle") { }

namespace Nettle_detail {

    template <class CTXType, size_t DigestSize>
    class Digest {
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
                init(init),
                update(update),
                digest(digest)
            { }

            std::optional<component::Digest> Run(operation::Digest& op) {
                std::optional<component::Digest> ret = std::nullopt;
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                util::Multipart parts;

                CTXType ctx;
                uint8_t digest[DigestSize];

                /* Initialize */
                {
                    parts = util::ToParts(ds, op.cleartext);
                    /* noret */ init(&ctx);
                }

                /* Process */
                for (const auto& part : parts) {
                    /* noret */ update(&ctx, part.second, part.first);
                }

                /* Finalize */
                {
                    /* noret */ this->digest(&ctx, DigestSize, digest);
                    ret = component::Digest(digest, DigestSize);
                }

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
    }

    return ret;
}

namespace Nettle_detail {

    template <class CTXType, size_t DigestSize>
    class HMAC {
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
                set_key(set_key),
                update(update),
                digest(digest)
            { }

            std::optional<component::MAC> Run(operation::HMAC& op) {
                std::optional<component::Digest> ret = std::nullopt;
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                util::Multipart parts;

                CTXType ctx;
                uint8_t digest[DigestSize];

                /* Initialize */
                {
                    parts = util::ToParts(ds, op.cleartext);
                    /* noret */ set_key(&ctx, op.cipher.key.GetSize(), op.cipher.key.GetPtr());
                }

                /* Process */
                for (const auto& part : parts) {
                    /* noret */ update(&ctx, part.second, part.first);
                }

                /* Finalize */
                {
                    /* noret */ this->digest(&ctx, DigestSize, digest);
                    ret = component::Digest(digest, DigestSize);
                }

                return ret;
            }
    };

    HMAC<hmac_md5_ctx, MD5_DIGEST_SIZE> hmac_md5(hmac_md5_set_key, hmac_md5_update, hmac_md5_digest);
    HMAC<hmac_ripemd160_ctx, RIPEMD160_DIGEST_SIZE> hmac_ripemd160(hmac_ripemd160_set_key, hmac_ripemd160_update, hmac_ripemd160_digest);
    HMAC<hmac_sha1_ctx, SHA1_DIGEST_SIZE> hmac_sha1(hmac_sha1_set_key, hmac_sha1_update, hmac_sha1_digest);
    HMAC<hmac_sha256_ctx, SHA256_DIGEST_SIZE> hmac_sha256(hmac_sha256_set_key, hmac_sha256_update, hmac_sha256_digest);
    HMAC<hmac_sha512_ctx, SHA512_DIGEST_SIZE> hmac_sha512(hmac_sha512_set_key, hmac_sha512_update, hmac_sha512_digest);

} /* namespace Nettle_detail */

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
    }

    return ret;
}

namespace Nettle_detail {

    template <class CTXType, size_t DigestSize, size_t KeySize>
    class CMAC {
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
                set_key(set_key),
                update(update),
                digest(digest)
            { }

            std::optional<component::MAC> Run(operation::CMAC& op) {
                std::optional<component::Digest> ret = std::nullopt;
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                util::Multipart parts;

                CTXType ctx;
                uint8_t digest[DigestSize];

                /* Initialize */
                {
                    CF_CHECK_EQ(op.cipher.key.GetSize(), KeySize);
                    parts = util::ToParts(ds, op.cleartext);
                    /* noret */ set_key(&ctx, op.cipher.key.GetPtr());
                }

                /* Process */
                for (const auto& part : parts) {
                    /* noret */ update(&ctx, part.second, part.first);
                }

                /* Finalize */
                {
                    /* noret */ this->digest(&ctx, DigestSize, digest);
                    ret = component::Digest(digest, DigestSize);
                }
end:

                return ret;
            }
    };

    CMAC<cmac_aes128_ctx, CMAC128_DIGEST_SIZE, 16> cmac_aes128(cmac_aes128_set_key, cmac_aes128_update, cmac_aes128_digest);
    CMAC<cmac_aes256_ctx, CMAC128_DIGEST_SIZE, 32> cmac_aes256(cmac_aes256_set_key, cmac_aes256_update, cmac_aes256_digest);
} /* namespace Nettle_detail */

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
