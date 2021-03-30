#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <tomcrypt.h>

namespace cryptofuzz {
namespace module {

libtomcrypt::libtomcrypt(void) :
    Module("libtomcrypt") {
    CF_CHECK_NE(register_hash(&md2_desc), -1);
    CF_CHECK_NE(register_hash(&md4_desc), -1);
    CF_CHECK_NE(register_hash(&md5_desc), -1);
    CF_CHECK_NE(register_hash(&rmd128_desc), -1);
    CF_CHECK_NE(register_hash(&rmd160_desc), -1);
    CF_CHECK_NE(register_hash(&rmd256_desc), -1);
    CF_CHECK_NE(register_hash(&rmd320_desc), -1);
    CF_CHECK_NE(register_hash(&sha1_desc), -1);
    CF_CHECK_NE(register_hash(&sha224_desc), -1);
    CF_CHECK_NE(register_hash(&sha256_desc), -1);
    CF_CHECK_NE(register_hash(&sha384_desc), -1);
    CF_CHECK_NE(register_hash(&sha512_desc), -1);
    CF_CHECK_NE(register_hash(&tiger_desc), -1);
    CF_CHECK_NE(register_hash(&whirlpool_desc), -1);

    CF_CHECK_NE(register_all_ciphers(), -1);

    return;

end:
    abort();
}

namespace libtomcrypt_detail {
    template <class OperationType, class ReturnType, class CTXType>
    class Operation {
        protected:
            CTXType ctx;
        public:
            Operation(void) { }
            ~Operation() { }
            virtual bool runInit(OperationType& op) = 0;
            virtual bool runUpdate(util::Multipart& parts) = 0;
            virtual std::optional<std::vector<uint8_t>> runFinalize(void) = 0;
            std::optional<ReturnType> Run(OperationType& op) {
                std::optional<ReturnType> ret = std::nullopt;

                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                util::Multipart parts;

                if ( runInit(op) == false ) {
                    return std::nullopt;
                }

                parts = util::ToParts(ds, op.cleartext);

                CF_CHECK_EQ(runUpdate(parts), true);

                {
                    auto res = runFinalize();
                    if ( res != std::nullopt ) {
                        return ReturnType(res->data(), res->size());
                    }
                }

end:
                return ret;
            }
    };

    template <size_t DigestSize, class CTXType = hash_state>
    class Digest : public Operation<operation::Digest, component::Digest, CTXType> {
        private:
            int (*init)(CTXType*);
            int (*update)(CTXType*, const uint8_t*, unsigned long);
            int (*digest)(CTXType*, uint8_t*);
        public:
            Digest(
                int (*init)(CTXType*),
                int (*update)(CTXType*, const uint8_t*, unsigned long),
                int (*digest)(CTXType*, uint8_t*)
            ) :
                Operation<operation::Digest, component::Digest, CTXType>(),
                init(init),
                update(update),
                digest(digest)
            { }

            bool runInit(operation::Digest& op) override {
                (void)op;
                bool ret = false;

                CF_CHECK_EQ(init(&this->ctx), CRYPT_OK);
                ret = true;

end:
                return ret;
            }

            bool runUpdate(util::Multipart& parts) override {
                bool ret = false;

                for (const auto& part : parts) {
                    if ( part.first == nullptr ) {
                        continue;
                    }
                    CF_CHECK_EQ(update(&this->ctx, part.first, part.second), CRYPT_OK);
                }

                ret = true;

end:
                return ret;
            }

            std::optional<std::vector<uint8_t>> runFinalize(void) override {
                std::optional<std::vector<uint8_t>> ret = std::nullopt;

                std::vector<uint8_t> _ret(DigestSize);
                CF_CHECK_EQ(digest(&this->ctx, _ret.data()), CRYPT_OK);

                ret = _ret;
end:
                return ret;
            }
    };

    static int _crc32_init(crc32_state *ctx) {
        /* noret */ crc32_init(ctx);

        return CRYPT_OK;
    }

    static int _crc32_update(crc32_state *ctx, const unsigned char *input, unsigned long length) {
        /* noret */ crc32_update(ctx, input, length);

        return CRYPT_OK;
    }

    static int _crc32_done(crc32_state* ctx, uint8_t* hash) {
        /* noret */ crc32_finish(ctx, hash, 4);

        return CRYPT_OK;
    }

    static int _adler32_init(adler32_state *ctx) {
        /* noret */ adler32_init(ctx);

        return CRYPT_OK;
    }

    static int _adler32_update(adler32_state *ctx, const unsigned char *input, unsigned long length) {
        /* noret */ adler32_update(ctx, input, length);

        return CRYPT_OK;
    }

    static int _adler32_done(adler32_state* ctx, uint8_t* hash) {
        /* noret */ adler32_finish(ctx, hash, 4);

        return CRYPT_OK;
    }

    Digest<4, crc32_state> crc32(_crc32_init, _crc32_update, _crc32_done);
    Digest<4, adler32_state> adler32(_adler32_init, _adler32_update, _adler32_done);
    Digest<16> md2(md2_init, md2_process, md2_done);
    Digest<16> md4(md4_init, md4_process, md4_done);
    Digest<16> md5(md5_init, md5_process, md5_done);
    Digest<16> ripemd128(rmd128_init, rmd128_process, rmd128_done);
    Digest<20> ripemd160(rmd160_init, rmd160_process, rmd160_done);
    Digest<32> ripemd256(rmd256_init, rmd256_process, rmd256_done);
    Digest<40> ripemd320(rmd320_init, rmd320_process, rmd320_done);
    Digest<20> sha1(sha1_init, sha1_process, sha1_done);
    Digest<28> sha224(sha224_init, sha224_process, sha224_done);
    Digest<32> sha256(sha256_init, sha256_process, sha256_done);
    Digest<48> sha384(sha384_init, sha384_process, sha384_done);
    Digest<64> sha512(sha512_init, sha512_process, sha512_done);
    Digest<24> tiger(tiger_init, tiger_process, tiger_done);
    Digest<64> whirlpool(whirlpool_init, whirlpool_process, whirlpool_done);
    Digest<20> blake2b160(blake2b_160_init, blake2b_process, blake2b_done);
    Digest<32> blake2b256(blake2b_256_init, blake2b_process, blake2b_done);
    Digest<48> blake2b384(blake2b_384_init, blake2b_process, blake2b_done);
    Digest<64> blake2b512(blake2b_512_init, blake2b_process, blake2b_done);
    Digest<16> blake2s128(blake2s_128_init, blake2s_process, blake2s_done);
    Digest<20> blake2s160(blake2s_160_init, blake2s_process, blake2s_done);
    Digest<28> blake2s224(blake2s_224_init, blake2s_process, blake2s_done);
    Digest<32> blake2s256(blake2s_256_init, blake2s_process, blake2s_done);
#if 0
    Digest<28> keccak224(keccak224_init, keccak224_process, keccak224_done);
    Digest<32> keccak256(keccak256_init, keccak256_process, keccak256_done);
    Digest<48> keccak384(keccak384_init, keccak384_process, keccak384_done);
    Digest<64> keccak512(keccak512_init, keccak512_process, keccak512_done);
#endif

    static int ToHashIdx(const uint64_t digestType) {
        switch ( digestType ) {
            case CF_DIGEST("MD2"):
                return find_hash("md2");
            case CF_DIGEST("MD4"):
                return find_hash("md4");
            case CF_DIGEST("MD5"):
                return find_hash("md5");
            case CF_DIGEST("RIPEMD128"):
                return find_hash("rmd128");
            case CF_DIGEST("RIPEMD160"):
                return find_hash("rmd160");
            case CF_DIGEST("RIPEMD256"):
                return find_hash("rmd256");
            case CF_DIGEST("RIPEMD320"):
                return find_hash("rmd320");
            case CF_DIGEST("SHA1"):
                return find_hash("sha1");
            case CF_DIGEST("SHA224"):
                return find_hash("sha224");
            case CF_DIGEST("SHA256"):
                return find_hash("sha256");
            case CF_DIGEST("SHA384"):
                return find_hash("sha384");
            case CF_DIGEST("SHA512"):
                return find_hash("sha512");
            case CF_DIGEST("TIGER"):
                return find_hash("tiger");
            case CF_DIGEST("WHIRLPOOL"):
                return find_hash("whirlpool");
            default:
                return -1;
        }
    }
} /* namespace libtomcrypt_detail */

std::optional<component::Digest> libtomcrypt::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("CRC32"):
            ret = libtomcrypt_detail::crc32.Run(op);
            break;
        case CF_DIGEST("ADLER32"):
            ret = libtomcrypt_detail::adler32.Run(op);
            break;
        case CF_DIGEST("MD2"):
            ret = libtomcrypt_detail::md2.Run(op);
            break;
        case CF_DIGEST("MD4"):
            ret = libtomcrypt_detail::md4.Run(op);
            break;
        case CF_DIGEST("MD5"):
            ret = libtomcrypt_detail::md5.Run(op);
            break;
        case CF_DIGEST("RIPEMD128"):
            ret = libtomcrypt_detail::ripemd128.Run(op);
            break;
        case CF_DIGEST("RIPEMD160"):
            ret = libtomcrypt_detail::ripemd160.Run(op);
            break;
        case CF_DIGEST("RIPEMD256"):
            ret = libtomcrypt_detail::ripemd256.Run(op);
            break;
        case CF_DIGEST("RIPEMD320"):
            ret = libtomcrypt_detail::ripemd320.Run(op);
            break;
        case CF_DIGEST("SHA1"):
            ret = libtomcrypt_detail::sha1.Run(op);
            break;
        case CF_DIGEST("SHA224"):
            ret = libtomcrypt_detail::sha224.Run(op);
            break;
        case CF_DIGEST("SHA256"):
            ret = libtomcrypt_detail::sha256.Run(op);
            break;
        case CF_DIGEST("SHA384"):
            ret = libtomcrypt_detail::sha384.Run(op);
            break;
        case CF_DIGEST("SHA512"):
            ret = libtomcrypt_detail::sha512.Run(op);
            break;
        case CF_DIGEST("TIGER"):
            ret = libtomcrypt_detail::tiger.Run(op);
            break;
        case CF_DIGEST("WHIRLPOOL"):
            ret = libtomcrypt_detail::whirlpool.Run(op);
            break;
        case CF_DIGEST("BLAKE2B160"):
            ret = libtomcrypt_detail::blake2b160.Run(op);
            break;
        case CF_DIGEST("BLAKE2B256"):
            ret = libtomcrypt_detail::blake2b256.Run(op);
            break;
        case CF_DIGEST("BLAKE2B384"):
            ret = libtomcrypt_detail::blake2b384.Run(op);
            break;
        case CF_DIGEST("BLAKE2B512"):
            ret = libtomcrypt_detail::blake2b512.Run(op);
            break;
        case CF_DIGEST("BLAKE2S128"):
            ret = libtomcrypt_detail::blake2s128.Run(op);
            break;
        case CF_DIGEST("BLAKE2S160"):
            ret = libtomcrypt_detail::blake2s160.Run(op);
            break;
        case CF_DIGEST("BLAKE2S224"):
            ret = libtomcrypt_detail::blake2s224.Run(op);
            break;
        case CF_DIGEST("BLAKE2S256"):
            ret = libtomcrypt_detail::blake2s256.Run(op);
            break;
#if 0
        case CF_DIGEST("KECCAK_224"):
            ret = libtomcrypt_detail::keccak224.Run(op);
            break;
        case CF_DIGEST("KECCAK_256"):
            ret = libtomcrypt_detail::keccak256.Run(op);
            break;
        case CF_DIGEST("KECCAK_384"):
            ret = libtomcrypt_detail::keccak384.Run(op);
            break;
        case CF_DIGEST("KECCAK_512"):
            ret = libtomcrypt_detail::keccak512.Run(op);
            break;
#endif
    }

    return ret;
}

std::optional<component::MAC> libtomcrypt::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    hmac_state ctx;
    uint8_t out[MAXBLOCKSIZE];
    unsigned long outlen = sizeof(out);
    int hashIdx = -1;
    util::Multipart parts;

    CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    CF_CHECK_EQ(hmac_init(&ctx, hashIdx, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), CRYPT_OK);

    parts = util::ToParts(ds, op.cleartext);
    for (const auto& part : parts) {
        if ( part.first == nullptr ) {
            continue;
        }
        CF_CHECK_EQ(hmac_process(&ctx, part.first, part.second), CRYPT_OK);
    }

    CF_CHECK_EQ(hmac_done(&ctx, out, &outlen), CRYPT_OK);

    ret = component::MAC(out, outlen);
end:
    return ret;
}

namespace libtomcrypt_detail {
    static int ToCipherIdx(const uint64_t cipherType) {
        switch ( cipherType ) {
            case CF_CIPHER("AES_128_GCM"):
            case CF_CIPHER("AES_192_GCM"):
            case CF_CIPHER("AES_256_GCM"):
            case CF_CIPHER("AES_128_CCM"):
            case CF_CIPHER("AES_192_CCM"):
            case CF_CIPHER("AES_256_CCM"):
            case CF_CIPHER("AES_128_ECB"):
            case CF_CIPHER("AES_192_ECB"):
            case CF_CIPHER("AES_256_ECB"):
            case CF_CIPHER("AES_128_CTR"):
            case CF_CIPHER("AES_192_CTR"):
            case CF_CIPHER("AES_256_CTR"):
            case CF_CIPHER("AES_128_CFB"):
            case CF_CIPHER("AES_192_CFB"):
            case CF_CIPHER("AES_256_CFB"):
            case CF_CIPHER("AES_128_OFB"):
            case CF_CIPHER("AES_192_OFB"):
            case CF_CIPHER("AES_256_OFB"):
            case CF_CIPHER("AES_128_CBC"):
            case CF_CIPHER("AES_192_CBC"):
            case CF_CIPHER("AES_256_CBC"):
                return find_cipher("aes");
            case CF_CIPHER("CAMELLIA_128_GCM"):
            case CF_CIPHER("CAMELLIA_192_GCM"):
            case CF_CIPHER("CAMELLIA_256_GCM"):
            case CF_CIPHER("CAMELLIA_128_CCM"):
            case CF_CIPHER("CAMELLIA_192_CCM"):
            case CF_CIPHER("CAMELLIA_256_CCM"):
            case CF_CIPHER("CAMELLIA_128_ECB"):
            case CF_CIPHER("CAMELLIA_192_ECB"):
            case CF_CIPHER("CAMELLIA_256_ECB"):
            case CF_CIPHER("CAMELLIA_128_CTR"):
            case CF_CIPHER("CAMELLIA_192_CTR"):
            case CF_CIPHER("CAMELLIA_256_CTR"):
            case CF_CIPHER("CAMELLIA_128_CFB"):
            case CF_CIPHER("CAMELLIA_192_CFB"):
            case CF_CIPHER("CAMELLIA_256_CFB"):
            case CF_CIPHER("CAMELLIA_128_OFB"):
            case CF_CIPHER("CAMELLIA_192_OFB"):
            case CF_CIPHER("CAMELLIA_256_OFB"):
            case CF_CIPHER("CAMELLIA_128_CBC"):
            case CF_CIPHER("CAMELLIA_192_CBC"):
            case CF_CIPHER("CAMELLIA_256_CBC"):
                return find_cipher("camellia");
            case CF_CIPHER("TWOFISH_ECB"):
            case CF_CIPHER("TWOFISH_CTR"):
            case CF_CIPHER("TWOFISH_CFB"):
            case CF_CIPHER("TWOFISH_OFB"):
            case CF_CIPHER("TWOFISH_CBC"):
                return find_cipher("twofish");
            case CF_CIPHER("IDEA_ECB"):
            case CF_CIPHER("IDEA_CTR"):
            case CF_CIPHER("IDEA_CFB"):
            case CF_CIPHER("IDEA_OFB"):
            case CF_CIPHER("IDEA_CBC"):
                return find_cipher("idea");
            case CF_CIPHER("CAST5_ECB"):
            case CF_CIPHER("CAST5_CTR"):
            case CF_CIPHER("CAST5_CFB"):
            case CF_CIPHER("CAST5_OFB"):
            case CF_CIPHER("CAST5_CBC"):
                return find_cipher("cast5");
            case CF_CIPHER("SKIPJACK_ECB"):
            case CF_CIPHER("SKIPJACK_CTR"):
            case CF_CIPHER("SKIPJACK_CFB"):
            case CF_CIPHER("SKIPJACK_OFB"):
            case CF_CIPHER("SKIPJACK_CBC"):
                return find_cipher("skipjack");
            case CF_CIPHER("BLOWFISH_ECB"):
            case CF_CIPHER("BLOWFISH_CTR"):
            case CF_CIPHER("BLOWFISH_CFB"):
            case CF_CIPHER("BLOWFISH_OFB"):
            case CF_CIPHER("BLOWFISH_CBC"):
                return find_cipher("blowfish");
            case CF_CIPHER("DES_ECB"):
            case CF_CIPHER("DES_CTR"):
            case CF_CIPHER("DES_CFB"):
            case CF_CIPHER("DES_OFB"):
            case CF_CIPHER("DES_CBC"):
                return find_cipher("des");
            case CF_CIPHER("RC2_ECB"):
            case CF_CIPHER("RC2_CTR"):
            case CF_CIPHER("RC2_CFB"):
            case CF_CIPHER("RC2_OFB"):
            case CF_CIPHER("RC2_CBC"):
                return find_cipher("rc2");
            case CF_CIPHER("XTEA_ECB"):
            case CF_CIPHER("XTEA_CTR"):
            case CF_CIPHER("XTEA_CFB"):
            case CF_CIPHER("XTEA_OFB"):
            case CF_CIPHER("XTEA_CBC"):
                return find_cipher("xtea");
            case CF_CIPHER("ANUBIS_ECB"):
            case CF_CIPHER("ANUBIS_CTR"):
            case CF_CIPHER("ANUBIS_CFB"):
            case CF_CIPHER("ANUBIS_OFB"):
            case CF_CIPHER("ANUBIS_CBC"):
                return find_cipher("anubis");
            case CF_CIPHER("KASUMI_ECB"):
            case CF_CIPHER("KASUMI_CTR"):
            case CF_CIPHER("KASUMI_CFB"):
            case CF_CIPHER("KASUMI_OFB"):
            case CF_CIPHER("KASUMI_CBC"):
                return find_cipher("kasumi");
            case CF_CIPHER("RC6_ECB"):
            case CF_CIPHER("RC6_CTR"):
            case CF_CIPHER("RC6_CFB"):
            case CF_CIPHER("RC6_OFB"):
            case CF_CIPHER("RC6_CBC"):
                return find_cipher("rc6");
            /* Pending fix for https://github.com/libtom/libtomcrypt/issues/553 */
#if 0
            case CF_CIPHER("TEA_ECB"):
            case CF_CIPHER("TEA_CBC"):
#endif
            case CF_CIPHER("TEA_CTR"):
            case CF_CIPHER("TEA_CFB"):
            case CF_CIPHER("TEA_OFB"):
                return find_cipher("tea");
            case CF_CIPHER("SEED_ECB"):
            case CF_CIPHER("SEED_CTR"):
            case CF_CIPHER("SEED_CFB"):
            case CF_CIPHER("SEED_OFB"):
            case CF_CIPHER("SEED_CBC"):
                return find_cipher("seed");
            case CF_CIPHER("KHAZAD_ECB"):
            case CF_CIPHER("KHAZAD_CTR"):
            case CF_CIPHER("KHAZAD_CFB"):
            case CF_CIPHER("KHAZAD_OFB"):
            case CF_CIPHER("KHAZAD_CBC"):
                return find_cipher("khazad");
            case CF_CIPHER("NOEKEON_DIRECT_ECB"):
            case CF_CIPHER("NOEKEON_DIRECT_CTR"):
            case CF_CIPHER("NOEKEON_DIRECT_CFB"):
            case CF_CIPHER("NOEKEON_DIRECT_OFB"):
            case CF_CIPHER("NOEKEON_DIRECT_CBC"):
                return find_cipher("noekeon");
            case CF_CIPHER("RC5_ECB"):
            case CF_CIPHER("RC5_CTR"):
            case CF_CIPHER("RC5_CFB"):
            case CF_CIPHER("RC5_OFB"):
            case CF_CIPHER("RC5_CBC"):
                return find_cipher("rc5");
            case CF_CIPHER("SERPENT_ECB"):
            case CF_CIPHER("SERPENT_CTR"):
            case CF_CIPHER("SERPENT_CFB"):
            case CF_CIPHER("SERPENT_OFB"):
            case CF_CIPHER("SERPENT_CBC"):
                return find_cipher("serpent");
            case CF_CIPHER("SAFER_K_ECB"):
            case CF_CIPHER("SAFER_K_CTR"):
            case CF_CIPHER("SAFER_K_CFB"):
            case CF_CIPHER("SAFER_K_OFB"):
            case CF_CIPHER("SAFER_K_CBC"):
                return find_cipher("safer-k64");
            case CF_CIPHER("SAFER_SK_ECB"):
            case CF_CIPHER("SAFER_SK_CTR"):
            case CF_CIPHER("SAFER_SK_CFB"):
            case CF_CIPHER("SAFER_SK_OFB"):
            case CF_CIPHER("SAFER_SK_CBC"):
                return find_cipher("safer-sk64");
            default:
                return -1;
        }
    }

    std::optional<component::Ciphertext> GcmEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }

        util::Multipart parts;
        gcm_state gcm;
        int cipherIdx = -1;

        int err = 0;
        uint8_t* tag = util::malloc(*op.tagSize);
        uint8_t* out = util::malloc(op.ciphertextSize);
        size_t outPos = 0;
        size_t left = op.ciphertextSize;

        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_EQ((err = gcm_init(&gcm, cipherIdx, op.cipher.key.GetPtr(), op.cipher.key.GetSize())), CRYPT_OK);

        CF_CHECK_EQ(gcm_add_iv(&gcm, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);

        if ( op.aad != std::nullopt ) {
            CF_CHECK_EQ(gcm_add_aad(&gcm, op.aad->GetPtr(), op.aad->GetSize()), CRYPT_OK);
        }

        for (const auto& part : parts) {
            CF_CHECK_GTE(left, part.second);
            std::vector<uint8_t> in(part.first, part.first + part.second);
            CF_CHECK_EQ(gcm_process(&gcm, in.data(), in.size(), out + outPos, GCM_ENCRYPT), CRYPT_OK);
            outPos += part.second;
            left -= part.second;
        }

        {
            unsigned long tag_len = *op.tagSize;
            CF_CHECK_NE(tag, nullptr);
            CF_CHECK_EQ(gcm_done(&gcm, tag, &tag_len), CRYPT_OK);
            ret = component::Ciphertext(Buffer(out, outPos), Buffer(tag, tag_len));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Cleartext> GcmDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        util::Multipart parts;
        gcm_state gcm;
        int cipherIdx = -1;

        int err = 0;
        if ( op.tag == std::nullopt ) {
            return ret;
        }
        uint8_t* tag = util::malloc(op.tag->GetSize());
        uint8_t* out = util::malloc(op.cleartextSize);
        size_t outPos = 0;
        size_t left = op.cleartextSize;

        parts = util::ToParts(ds, op.ciphertext);

        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_EQ((err = gcm_init(&gcm, cipherIdx, op.cipher.key.GetPtr(), op.cipher.key.GetSize())), CRYPT_OK);

        CF_CHECK_EQ(gcm_add_iv(&gcm, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);

        if ( op.aad != std::nullopt ) {
            CF_CHECK_EQ(gcm_add_aad(&gcm, op.aad->GetPtr(), op.aad->GetSize()), CRYPT_OK);
        }

        for (const auto& part : parts) {
            CF_CHECK_GTE(left, part.second);
            std::vector<uint8_t> in(part.first, part.first + part.second);
            CF_CHECK_EQ(gcm_process(&gcm, out + outPos, in.size(), in.data(), GCM_DECRYPT), CRYPT_OK);
            outPos += part.second;
            left -= part.second;
        }

        {
            unsigned long tag_len = op.tag->GetSize();
            CF_CHECK_NE(tag, nullptr);
            CF_CHECK_EQ(gcm_done(&gcm, tag, &tag_len), CRYPT_OK);

            /* Verify tag */
            CF_CHECK_EQ(tag_len, op.tag->GetSize());
            CF_CHECK_EQ(memcmp(tag, op.tag->GetPtr(), op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, outPos));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Ciphertext> CcmEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }

        /* Prevent Wycheproof CCM test in tests.cpp failing.
         * There is a libtomcrypt PR for this, but not yet merged:
         * https://github.com/libtom/libtomcrypt/pull/452
         */
        if ( op.cipher.iv.GetSize() < 7 || op.cipher.iv.GetSize() > 13 ) {
            return ret;
        }

        auto oneshot = false;
        try { oneshot = ds.Get<bool>(); } catch ( ... ) { }

        uint8_t* tag = util::malloc(*op.tagSize);
        uint8_t* out = util::malloc(op.ciphertextSize);
        int cipherIdx = -1;

        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);

        {
            unsigned long tag_len = *op.tagSize;
            auto in = op.cleartext.Get();
            CF_CHECK_NE(tag, nullptr);
            CF_CHECK_NE(in.data(), nullptr);
            CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
            CF_CHECK_NE(op.cipher.iv.GetPtr(), nullptr);
            if ( oneshot == true ) {
                /* One-shot */

                CF_CHECK_EQ(ccm_memory(
                            cipherIdx,
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            nullptr,
                            op.cipher.iv.GetPtr(),
                            op.cipher.iv.GetSize(),
                            op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0,
                            in.data(),
                            in.size(),
                            out,
                            tag,
                            &tag_len,
                            CCM_ENCRYPT), CRYPT_OK);
            } else {
                /* Multi-step */

                ccm_state ccm;
                CF_CHECK_EQ(ccm_init(
                            &ccm,
                            cipherIdx,
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            in.size(),
                            tag_len,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                CF_CHECK_EQ(ccm_add_nonce(&ccm, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);
                if ( op.aad != std::nullopt && op.aad->GetPtr() != nullptr ) {
                    CF_CHECK_EQ(ccm_add_aad(
                                &ccm,
                                op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                                op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                }
                CF_CHECK_EQ(ccm_process(&ccm, in.data(), in.size(), out, CCM_ENCRYPT), CRYPT_OK);
                CF_CHECK_EQ(ccm_done(&ccm, tag, &tag_len), CRYPT_OK);
            }

            ret = component::Ciphertext(Buffer(out, in.size()), Buffer(tag, tag_len));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Cleartext> CcmDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tag == std::nullopt ) {
            return ret;
        }

        /* See CcmEncrypt */
        if ( op.cipher.iv.GetSize() < 7 || op.cipher.iv.GetSize() > 13 ) {
            return ret;
        }

        auto oneshot = false;
        try { oneshot = ds.Get<bool>(); } catch ( ... ) { }

        uint8_t* tag = util::malloc(op.tag->GetSize());
        uint8_t* out = util::malloc(op.cleartextSize);
        int cipherIdx = -1;

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);

        {
            unsigned long tag_len = op.tag->GetSize();
            auto in = op.ciphertext.Get();
            auto tag = op.tag->Get();
            CF_CHECK_NE(tag.data(), nullptr);
            CF_CHECK_NE(in.data(), nullptr);
            CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
            CF_CHECK_NE(op.cipher.iv.GetPtr(), nullptr);

            if ( oneshot == true ) {
                /* One-shot */

                CF_CHECK_EQ(ccm_memory(
                            cipherIdx,
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            nullptr,
                            op.cipher.iv.GetPtr(),
                            op.cipher.iv.GetSize(),
                            op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0,
                            out,
                            in.size(),
                            in.data(),
                            tag.data(),
                            &tag_len,
                            CCM_DECRYPT), CRYPT_OK);
            } else {
                /* Multi-step */

                ccm_state ccm;
                CF_CHECK_EQ(ccm_init(
                            &ccm,
                            cipherIdx,
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            in.size(),
                            tag_len,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                CF_CHECK_EQ(ccm_add_nonce(&ccm, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);
                if ( op.aad != std::nullopt && op.aad->GetPtr() != nullptr ) {
                    CF_CHECK_EQ(ccm_add_aad(
                                &ccm,
                                op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                                op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                }
                CF_CHECK_EQ(ccm_process(&ccm, out, in.size(), in.data(), CCM_DECRYPT), CRYPT_OK);
                CF_CHECK_EQ(ccm_done(&ccm, tag.data(), &tag_len), CRYPT_OK);
            }

            ret = component::Cleartext(Buffer(out, in.size()));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Ciphertext> ChaCha20Poly1305Encrypt(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }

        if ( *op.tagSize < 16 ) {
            return ret;
        }

        if ( op.cipher.key.GetSize() != 16 && op.cipher.key.GetSize() != 32 ) {
            return ret;
        }

        if ( op.cipher.iv.GetSize() != 8 && op.cipher.iv.GetSize() != 12 ) {
            return ret;
        }

        auto oneshot = false;
        try { oneshot = ds.Get<bool>(); } catch ( ... ) { }

        uint8_t* tag = util::malloc(*op.tagSize);
        uint8_t* out = util::malloc(op.ciphertextSize);

        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        {
            unsigned long tag_len = *op.tagSize;
            auto in = op.cleartext.Get();
            CF_CHECK_NE(tag, nullptr);
            CF_CHECK_NE(in.data(), nullptr);
            CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
            CF_CHECK_NE(op.cipher.iv.GetPtr(), nullptr);
            if ( oneshot == true ) {
                /* One-shot */

                CF_CHECK_EQ(chacha20poly1305_memory(
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            op.cipher.iv.GetPtr(),
                            op.cipher.iv.GetSize(),
                            op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0,
                            in.data(),
                            in.size(),
                            out,
                            tag,
                            &tag_len,
                            CHACHA20POLY1305_ENCRYPT), CRYPT_OK);
            } else {
                /* Multi-step */

                chacha20poly1305_state state;
                size_t outIdx = 0;
                const auto parts = util::ToParts(ds, op.cleartext);

                CF_CHECK_EQ(chacha20poly1305_init(&state, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), CRYPT_OK);
                CF_CHECK_EQ(chacha20poly1305_setiv(&state, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);

                if ( op.aad != std::nullopt && op.aad->GetPtr() != nullptr ) {
                    CF_CHECK_EQ(chacha20poly1305_add_aad(
                                &state,
                                op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                                op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                }

                for (const auto& part : parts) {
                    CF_CHECK_EQ(chacha20poly1305_encrypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
                    outIdx += part.second;
                }

                CF_CHECK_EQ(chacha20poly1305_done(&state, tag, &tag_len), CRYPT_OK);
            }

            ret = component::Ciphertext(Buffer(out, in.size()), Buffer(tag, tag_len));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Cleartext> ChaCha20Poly1305Decrypt(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tag == std::nullopt ) {
            return ret;
        }

        if ( op.tag->GetSize() < 16 ) {
            return ret;
        }

        if ( op.cipher.key.GetSize() != 16 && op.cipher.key.GetSize() != 32 ) {
            return ret;
        }

        if ( op.cipher.iv.GetSize() != 8 && op.cipher.iv.GetSize() != 12 ) {
            return ret;
        }

        auto oneshot = false;
        try { oneshot = ds.Get<bool>(); } catch ( ... ) { }

        uint8_t* tag = util::malloc(op.tag->GetSize());
        uint8_t* out = util::malloc(op.cleartextSize);

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        {
            unsigned long tag_len = op.tag->GetSize();
            auto in = op.ciphertext.Get();
            auto tag = op.tag->Get();
            CF_CHECK_NE(tag.data(), nullptr);
            CF_CHECK_NE(in.data(), nullptr);
            CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
            CF_CHECK_NE(op.cipher.iv.GetPtr(), nullptr);

            if ( oneshot == true ) {
                /* One-shot */
                CF_CHECK_EQ(chacha20poly1305_memory(
                            op.cipher.key.GetPtr(),
                            op.cipher.key.GetSize(),
                            op.cipher.iv.GetPtr(),
                            op.cipher.iv.GetSize(),
                            op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                            op.aad != std::nullopt ? op.aad->GetSize() : 0,
                            in.data(),
                            in.size(),
                            out,
                            tag.data(),
                            &tag_len,
                            CHACHA20POLY1305_DECRYPT), CRYPT_OK);
            } else {
                chacha20poly1305_state state;
                size_t outIdx = 0;
                const auto parts = util::ToParts(ds, op.ciphertext);

                CF_CHECK_EQ(chacha20poly1305_init(&state, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), CRYPT_OK);
                CF_CHECK_EQ(chacha20poly1305_setiv(&state, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), CRYPT_OK);

                if ( op.aad != std::nullopt && op.aad->GetPtr() != nullptr ) {
                    CF_CHECK_EQ(chacha20poly1305_add_aad(
                                &state,
                                op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                                op.aad != std::nullopt ? op.aad->GetSize() : 0), CRYPT_OK);
                }

                for (const auto& part : parts) {
                    CF_CHECK_EQ(chacha20poly1305_decrypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
                    outIdx += part.second;
                }

                CF_CHECK_EQ(chacha20poly1305_done(&state, tag.data(), &tag_len), CRYPT_OK);
            }

            ret = component::Cleartext(Buffer(out, in.size()));
        }

    end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<Buffer> Salsa20Crypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher, const size_t keySize, const size_t rounds) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.iv.GetSize() != 8 ) {
            return ret;
        }

        if ( cipher.key.GetSize() != keySize ) {
            return ret;
        }

        salsa20_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(salsa20_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize(), rounds), CRYPT_OK);
        CF_CHECK_EQ(salsa20_ivctr64(&state, cipher.iv.GetPtr(), cipher.iv.GetSize(), 0), CRYPT_OK);
        for (const auto& part : parts) {
            CF_CHECK_EQ(salsa20_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> ChaCha20Crypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.iv.GetSize() != 8 ) {
            return ret;
        }

        if ( cipher.key.GetSize() != 16 && cipher.key.GetSize() != 32 ) {
            return ret;
        }

        chacha_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(chacha_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize(), 20), CRYPT_OK);
        CF_CHECK_EQ(chacha_ivctr64(&state, cipher.iv.GetPtr(), cipher.iv.GetSize(), 0), CRYPT_OK);
        for (const auto& part : parts) {
            CF_CHECK_EQ(chacha_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> RABBITCrypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.iv.GetSize() > 8 ) {
            return ret;
        }

        if ( cipher.key.GetSize() == 0 || cipher.key.GetSize() > 16 ) {
            return ret;
        }

        rabbit_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(rabbit_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize()), CRYPT_OK);
        CF_CHECK_EQ(rabbit_setiv(&state, cipher.iv.GetPtr(), cipher.iv.GetSize()), CRYPT_OK);
        for (const auto& part : parts) {
            CF_CHECK_EQ(rabbit_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> SOSEMANUKCrypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.iv.GetSize() > 16 ) {
            return ret;
        }

        if ( cipher.key.GetSize() == 0 || cipher.key.GetSize() > 32 ) {
            return ret;
        }

        sosemanuk_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(sosemanuk_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize()), CRYPT_OK);
        CF_CHECK_EQ(sosemanuk_setiv(&state, cipher.iv.GetPtr(), cipher.iv.GetSize()), CRYPT_OK);
        for (const auto& part : parts) {
            if ( part.first == nullptr ) {
                continue;
            }
            CF_CHECK_EQ(sosemanuk_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> RC4Crypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.key.GetSize() < 5 ) {
            return ret;
        }

        rc4_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(rc4_stream_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize()), CRYPT_OK);
        for (const auto& part : parts) {
            if ( part.first == nullptr ) {
                continue;
            }
            CF_CHECK_EQ(rc4_stream_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> SOBER128Crypt(Datasource& ds, const Buffer& in, const component::SymmetricCipher& cipher) {
        std::optional<Buffer> ret = std::nullopt;

        if ( cipher.iv.GetSize() == 0 ) {
            return ret;
        }

        if ( cipher.key.GetSize() == 0 ) {
            return ret;
        }

        sober128_state state;
        size_t outIdx = 0;

        uint8_t* out = util::malloc(in.GetSize());
        const auto parts = util::ToParts(ds, in);

        CF_CHECK_EQ(sober128_stream_setup(&state, cipher.key.GetPtr(), cipher.key.GetSize()), CRYPT_OK);
        CF_CHECK_EQ(sober128_stream_setiv(&state, cipher.iv.GetPtr(), cipher.iv.GetSize()), CRYPT_OK);
        for (const auto& part : parts) {
            CF_CHECK_EQ(sober128_stream_crypt(&state, part.first, part.second, out + outIdx), CRYPT_OK);
            outIdx += part.second;
        }

        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> EcbEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_ECB ecb;
        uint8_t* out = util::malloc(op.cleartext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.cleartext.GetSize(), 0);
        CF_CHECK_EQ(ecb_start(cipherIdx, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &ecb), CRYPT_OK);
        CF_CHECK_EQ(ecb_encrypt(op.cleartext.GetPtr(), out, op.cleartext.GetSize(), &ecb), CRYPT_OK);
        CF_CHECK_EQ(ecb_done(&ecb), CRYPT_OK);

        ret = Buffer(out, op.cleartext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> EcbDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_ECB ecb;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_EQ(ecb_start(cipherIdx, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &ecb), CRYPT_OK);
        CF_CHECK_EQ(ecb_decrypt(op.ciphertext.GetPtr(), out, op.ciphertext.GetSize(), &ecb), CRYPT_OK);
        CF_CHECK_EQ(ecb_done(&ecb), CRYPT_OK);

        ret = Buffer(out, op.ciphertext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CtrEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CTR ctr;
        uint8_t* out = util::malloc(op.cleartext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.cleartext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(ctr_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, CTR_COUNTER_BIG_ENDIAN, &ctr), CRYPT_OK);
        CF_CHECK_EQ(ctr_encrypt(op.cleartext.GetPtr(), out, op.cleartext.GetSize(), &ctr), CRYPT_OK);
        CF_CHECK_EQ(ctr_done(&ctr), CRYPT_OK);

        ret = Buffer(out, op.cleartext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CtrDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CTR ctr;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(ctr_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, CTR_COUNTER_BIG_ENDIAN, &ctr), CRYPT_OK);
        CF_CHECK_EQ(ctr_decrypt(op.ciphertext.GetPtr(), out, op.ciphertext.GetSize(), &ctr), CRYPT_OK);
        CF_CHECK_EQ(ctr_done(&ctr), CRYPT_OK);

        ret = Buffer(out, op.ciphertext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CfbEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CFB cfb;
        uint8_t* out = util::malloc(op.cleartext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.cleartext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(cfb_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &cfb), CRYPT_OK);
        CF_CHECK_EQ(cfb_encrypt(op.cleartext.GetPtr(), out, op.cleartext.GetSize(), &cfb), CRYPT_OK);
        CF_CHECK_EQ(cfb_done(&cfb), CRYPT_OK);

        ret = Buffer(out, op.cleartext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CfbDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CFB cfb;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(cfb_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &cfb), CRYPT_OK);
        CF_CHECK_EQ(cfb_decrypt(op.ciphertext.GetPtr(), out, op.ciphertext.GetSize(), &cfb), CRYPT_OK);
        CF_CHECK_EQ(cfb_done(&cfb), CRYPT_OK);

        ret = Buffer(out, op.ciphertext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> OfbEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_OFB ofb;
        uint8_t* out = util::malloc(op.cleartext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.cleartext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(ofb_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &ofb), CRYPT_OK);
        CF_CHECK_EQ(ofb_encrypt(op.cleartext.GetPtr(), out, op.cleartext.GetSize(), &ofb), CRYPT_OK);
        CF_CHECK_EQ(ofb_done(&ofb), CRYPT_OK);

        ret = Buffer(out, op.cleartext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> OfbDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_OFB ofb;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(ofb_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &ofb), CRYPT_OK);
        CF_CHECK_EQ(ofb_decrypt(op.ciphertext.GetPtr(), out, op.ciphertext.GetSize(), &ofb), CRYPT_OK);
        CF_CHECK_EQ(ofb_done(&ofb), CRYPT_OK);

        ret = Buffer(out, op.ciphertext.GetSize());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CbcEncrypt(operation::SymmetricEncrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CBC cbc;
        uint8_t* out = nullptr;
        std::vector<uint8_t> cleartext;

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        cleartext = util::Pkcs7Pad(op.cleartext.Get(), cipher_descriptor[cipherIdx].block_length);
        out = util::malloc(cleartext.size());
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(cleartext.size(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(cbc_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &cbc), CRYPT_OK);
        CF_CHECK_EQ(cbc_encrypt(cleartext.data(), out, cleartext.size(), &cbc), CRYPT_OK);
        CF_CHECK_EQ(cbc_done(&cbc), CRYPT_OK);

        ret = Buffer(out, cleartext.size());

end:
        util::free(out);
        return ret;
    }

    std::optional<Buffer> CbcDecrypt(operation::SymmetricDecrypt& op) {
        std::optional<Buffer> ret = std::nullopt;

        int cipherIdx = -1;
        symmetric_CBC cbc;
        uint8_t* out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_NE(cipherIdx = libtomcrypt_detail::ToCipherIdx(op.cipher.cipherType.Get()), -1);
        CF_CHECK_NE(op.cipher.key.GetPtr(), nullptr);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), (size_t)cipher_descriptor[cipherIdx].block_length);
        CF_CHECK_EQ(cbc_start(cipherIdx, op.cipher.iv.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), 0, &cbc), CRYPT_OK);
        CF_CHECK_EQ(cbc_decrypt(op.ciphertext.GetPtr(), out, op.ciphertext.GetSize(), &cbc), CRYPT_OK);
        CF_CHECK_EQ(cbc_done(&cbc), CRYPT_OK);

        {
            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), cipher_descriptor[cipherIdx].block_length);
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }

end:
        util::free(out);
        return ret;
    }

} /* namespace libtomcrypt_detail */

std::optional<component::Ciphertext> libtomcrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( repository::IsGCM(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::GcmEncrypt(op);
    } else if ( repository::IsCCM(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CcmEncrypt(op);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20_POLY1305") ) {
        return libtomcrypt_detail::ChaCha20Poly1305Encrypt(op);
    } else if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::EcbEncrypt(op);
    } else if ( repository::IsCTR(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CtrEncrypt(op);
    } else if ( repository::IsCFB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CfbEncrypt(op);
    } else if ( repository::IsOFB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::OfbEncrypt(op);
    } else if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CbcEncrypt(op);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
        return libtomcrypt_detail::ChaCha20Crypt(ds, op.cleartext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("RABBIT") ) {
        return libtomcrypt_detail::RABBITCrypt(ds, op.cleartext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SOSEMANUK") ) {
        return libtomcrypt_detail::SOSEMANUKCrypt(ds, op.cleartext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("RC4") ) {
        return libtomcrypt_detail::RC4Crypt(ds, op.cleartext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SOBER128") ) {
        return libtomcrypt_detail::SOBER128Crypt(ds, op.cleartext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_128") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.cleartext, op.cipher, 16, 20);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_12_128") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.cleartext, op.cipher, 16, 12);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_256") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.cleartext, op.cipher, 32, 20);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_12_256") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.cleartext, op.cipher, 32, 12);
    }

    return std::nullopt;
}

std::optional<component::Cleartext> libtomcrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( repository::IsGCM(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::GcmDecrypt(op);
    } else if ( repository::IsCCM(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CcmDecrypt(op);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20_POLY1305") ) {
        return libtomcrypt_detail::ChaCha20Poly1305Decrypt(op);
    } else if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::EcbDecrypt(op);
    } else if ( repository::IsCTR(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CtrDecrypt(op);
    } else if ( repository::IsCFB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CfbDecrypt(op);
    } else if ( repository::IsOFB(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::OfbDecrypt(op);
    } else if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
        return libtomcrypt_detail::CbcDecrypt(op);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
        return libtomcrypt_detail::ChaCha20Crypt(ds, op.ciphertext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("RABBIT") ) {
        return libtomcrypt_detail::RABBITCrypt(ds, op.ciphertext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SOSEMANUK") ) {
        return libtomcrypt_detail::SOSEMANUKCrypt(ds, op.ciphertext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("RC4") ) {
        return libtomcrypt_detail::RC4Crypt(ds, op.ciphertext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SOBER128") ) {
        return libtomcrypt_detail::SOBER128Crypt(ds, op.ciphertext, op.cipher);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_128") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.ciphertext, op.cipher, 16, 20);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_12_128") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.ciphertext, op.cipher, 16, 12);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_256") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.ciphertext, op.cipher, 32, 20);
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("SALSA20_12_256") ) {
        return libtomcrypt_detail::Salsa20Crypt(ds, op.ciphertext, op.cipher, 32, 12);
    }

    return std::nullopt;
}

std::optional<component::Key> libtomcrypt::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    int hashIdx = -1;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(out, nullptr);
    CF_CHECK_NE(op.password.GetPtr(), nullptr);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    CF_CHECK_EQ(hkdf(
                hashIdx,
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.info.GetPtr(),
                op.info.GetSize(),
                op.password.GetPtr(),
                op.password.GetSize(),
                out,
                op.keySize), CRYPT_OK);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

extern "C" {
    int pkcs12_kdf(               int   hash_id,
               const unsigned char *pw,         unsigned long pwlen,
               const unsigned char *salt,       unsigned long saltlen,
                     unsigned int   iterations, unsigned char purpose,
                     unsigned char *out,        unsigned long outlen);
}

std::optional<component::Key> libtomcrypt::OpKDF_PBKDF(operation::KDF_PBKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    int hashIdx = -1;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(out, nullptr);
    CF_CHECK_NE(op.password.GetPtr(), nullptr);
    CF_CHECK_NE(op.salt.GetPtr(), nullptr);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    CF_CHECK_EQ(pkcs12_kdf(hashIdx,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations, 1,
                out, op.keySize), CRYPT_OK);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> libtomcrypt::OpKDF_PBKDF1(operation::KDF_PBKDF1& op) {
    std::optional<component::Key> ret = std::nullopt;
    int hashIdx = -1;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(out, nullptr);
    CF_CHECK_NE(op.password.GetPtr(), nullptr);
    CF_CHECK_NE(op.salt.GetPtr(), nullptr);
    /* TODO report: iterations = 0 hangs */
    CF_CHECK_GT(op.iterations, 0);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    {
        unsigned long outLen = op.keySize;
        CF_CHECK_EQ(op.salt.GetSize(), 8);
        CF_CHECK_EQ(pkcs_5_alg1(
                    op.password.GetPtr(),
                    op.password.GetSize(),
                    op.salt.GetPtr(),
                    op.iterations,
                    hashIdx,
                    out,
                    &outLen), CRYPT_OK);

        CF_CHECK_EQ(outLen, op.keySize);
        ret = component::Key(out, outLen);
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> libtomcrypt::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    int hashIdx = -1;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(out, nullptr);
    CF_CHECK_NE(op.password.GetPtr(), nullptr);
    CF_CHECK_NE(op.salt.GetPtr(), nullptr);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    {
        unsigned long outLen = op.keySize;

        CF_CHECK_EQ(pkcs_5_alg2(
                    op.password.GetPtr(),
                    op.password.GetSize(),
                    op.salt.GetPtr(),
                    op.salt.GetSize(),
                    op.iterations,
                    hashIdx,
                    out,
                    &outLen), CRYPT_OK);

        ret = component::Key(out, outLen);
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> libtomcrypt::OpKDF_BCRYPT(operation::KDF_BCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    /* bcrypt currently disabled because it leads to OOMs */
    return ret;

    int hashIdx = -1;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(out, nullptr);
    CF_CHECK_NE(op.iterations, 0);
    CF_CHECK_NE(op.secret.GetPtr(), nullptr);
    CF_CHECK_NE(op.salt.GetPtr(), nullptr);

    CF_CHECK_NE(hashIdx = libtomcrypt_detail::ToHashIdx(op.digestType.Get()), -1);

    {
        unsigned long outLen = op.keySize;
        CF_CHECK_EQ(bcrypt_pbkdf_openbsd(
                    op.secret.GetPtr(),
                    op.secret.GetSize(),
                    op.salt.GetPtr(),
                    op.salt.GetSize(),
                    op.iterations,
                    hashIdx,
                    out,
                    &outLen), CRYPT_OK);

        ret = component::Key(out, outLen);
    }

end:
    util::free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
