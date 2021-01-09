#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>

extern "C" {
#include <sha1.h>
#include <sha2.h>
#include <sha3.h>
#include <hmac.h>
#include <pbkdf2.h>
#include <salsa20.h>
void cf_chacha20poly1305_encrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *header, size_t nheader,
                                 const uint8_t *plaintext, size_t nbytes,
                                 uint8_t *ciphertext,
                                 uint8_t tag[16]);
int cf_chacha20poly1305_decrypt(const uint8_t key[32],
                                const uint8_t nonce[12],
                                const uint8_t *header, size_t nheader,
                                const uint8_t *ciphertext, size_t nbytes,
                                const uint8_t tag[16],
                                uint8_t *plaintext);
}

namespace cryptofuzz {
namespace module {

cifra::cifra(void) :
    Module("cifra") {
}

namespace cifra_detail {
    const cf_chash* To_chash(const component::DigestType& digestType, const bool noSha3 = false) {
        switch ( digestType.Get() ) {
            case    CF_DIGEST("SHA1"):
                return &cf_sha1;
            case    CF_DIGEST("SHA224"):
                return &cf_sha224;
            case    CF_DIGEST("SHA256"):
                return &cf_sha256;
            case    CF_DIGEST("SHA384"):
                return &cf_sha384;
            case    CF_DIGEST("SHA512"):
                return &cf_sha512;
            case    CF_DIGEST("SHA3-224"):
                if ( noSha3 ) return nullptr;
                return &cf_sha3_224;
            case    CF_DIGEST("SHA3-256"):
                if ( noSha3 ) return nullptr;
                return &cf_sha3_256;
            case    CF_DIGEST("SHA3-384"):
                if ( noSha3 ) return nullptr;
                return &cf_sha3_384;
            case    CF_DIGEST("SHA3-512"):
                if ( noSha3 ) return nullptr;
                return &cf_sha3_512;
        }

        return nullptr;
    }
}

std::optional<component::Digest> cifra::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    cf_chash_ctx ctx;
    const cf_chash* chash;
    uint8_t* out = nullptr;

    CF_CHECK_NE(chash = cifra_detail::To_chash(op.digestType), nullptr);

    /* noret */ chash->init(&ctx);

    out = util::malloc(chash->hashsz);

    {
        auto parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : parts) {
            /* noret */ chash->update(&ctx, part.first, part.second);
        }
    }

    /* noret */ chash->digest(&ctx, out);

    ret = component::Digest(out, chash->hashsz);

end:
    util::free(out);
    return ret;
}

std::optional<component::MAC> cifra::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    cf_hmac_ctx ctx;
    const cf_chash* chash;
    uint8_t* out = nullptr;
    size_t hashsz = 0;

    CF_CHECK_NE(chash = cifra_detail::To_chash(op.digestType, true), nullptr);

    /* noret */ cf_hmac_init(&ctx, chash, op.cipher.key.GetPtr(), op.cipher.key.GetSize());

    hashsz = ctx.hash->hashsz;
    out = util::malloc(ctx.hash->hashsz);

    {
        auto parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : parts) {
            /* noret */ cf_hmac_update(&ctx, part.first, part.second);
        }
    }

    /* noret */ cf_hmac_finish(&ctx, out);

    //ret = component::MAC(out, ctx.hash->hashsz);
    ret = component::MAC(out, hashsz);

end:
    util::free(out);
    return ret;
}

std::optional<component::Ciphertext> cifra::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                CF_CHECK_NE(op.tagSize, std::nullopt);
                CF_CHECK_EQ(*op.tagSize, 16);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_NE(op.aad, std::nullopt);

                uint8_t tag[16];
                out = util::malloc(op.cleartext.GetSize());

                /* noret */ cf_chacha20poly1305_encrypt(
                        op.cipher.key.GetPtr(),
                        op.cipher.iv.GetPtr(),
                        op.aad->GetPtr(), op.aad->GetSize(),
                        op.cleartext.GetPtr(), op.cleartext.GetSize(),
                        out,
                        tag);

                ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(tag, sizeof(tag)));
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);
                CF_CHECK_TRUE(op.cipher.key.GetSize() == 16 || op.cipher.key.GetSize() == 32);

                cf_chacha20_ctx ctx;
                out = util::malloc(op.cleartext.GetSize());

                /* noret */ cf_chacha20_init(
                        &ctx,
                        op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr());

                auto parts = util::ToParts(ds, op.cleartext);
                size_t idx = 0;
                for (const auto& part : parts) {
                    /* noret */ cf_chacha20_cipher(
                            &ctx,
                            part.first,
                            out + idx,
                            part.second);
                    idx += part.second;
                }

                ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
            }
            break;
    }

end:
    util::free(out);
    return ret;
}

std::optional<component::Cleartext> cifra::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                CF_CHECK_NE(op.tag, std::nullopt);
                CF_CHECK_EQ(op.tag->GetSize(), 16);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_NE(op.aad, std::nullopt);

                out = util::malloc(op.ciphertext.GetSize());

                CF_CHECK_EQ(cf_chacha20poly1305_decrypt(
                        op.cipher.key.GetPtr(),
                        op.cipher.iv.GetPtr(),
                        op.aad->GetPtr(), op.aad->GetSize(),
                        op.ciphertext.GetPtr(), op.ciphertext.GetSize(),
                        op.tag->GetPtr(),
                        out), 0);

                ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);
                CF_CHECK_TRUE(op.cipher.key.GetSize() == 16 || op.cipher.key.GetSize() == 32);

                cf_chacha20_ctx ctx;
                out = util::malloc(op.ciphertext.GetSize());

                /* noret */ cf_chacha20_init(
                        &ctx,
                        op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr());

                auto parts = util::ToParts(ds, op.ciphertext);
                size_t idx = 0;
                for (const auto& part : parts) {
                    /* noret */ cf_chacha20_cipher(
                            &ctx,
                            part.first,
                            out + idx,
                            part.second);
                    idx += part.second;
                }

                ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
            }
            break;
    }

end:
    util::free(out);
    return ret;
}

std::optional<component::Key> cifra::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const cf_chash* chash;
    uint8_t* out = nullptr;

    CF_CHECK_NE(op.iterations, 0);
    CF_CHECK_NE(op.keySize, 0);
    CF_CHECK_NE(chash = cifra_detail::To_chash(op.digestType, true), nullptr);

    out = util::malloc(op.keySize);

    /* noret */ cf_pbkdf2_hmac(
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.iterations,
            out, op.keySize,
            chash);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
