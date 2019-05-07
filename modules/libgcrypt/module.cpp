#include "module.h"
#include <cryptofuzz/util.h>
#include <gcrypt.h>

namespace cryptofuzz {
namespace module {

libgcrypt::libgcrypt(void) :
    Module("libgcrypt") {
    if ( !gcry_check_version(GCRYPT_VERSION) ) {
        abort();
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN, 0);
}


std::optional<component::Digest> libgcrypt::OpDigest(operation::Digest& op) {
    static const std::map<uint64_t, int> LUT = {
        { CF_DIGEST("SHA1"), GCRY_MD_SHA1 },
        { CF_DIGEST("SHA224"), GCRY_MD_SHA224 },
        { CF_DIGEST("SHA256"), GCRY_MD_SHA256 },
        { CF_DIGEST("SHA384"), GCRY_MD_SHA384 },
        { CF_DIGEST("SHA512"), GCRY_MD_SHA512 },
        { CF_DIGEST("MD4"), GCRY_MD_MD4 },
        { CF_DIGEST("MD5"), GCRY_MD_MD5 },
        { CF_DIGEST("RIPEMD160"), GCRY_MD_RMD160 },
        { CF_DIGEST("WHIRLPOOL"), GCRY_MD_WHIRLPOOL },
        { CF_DIGEST("BLAKE2B512"), GCRY_MD_BLAKE2B_512 },
        { CF_DIGEST("BLAKE2S256"), GCRY_MD_BLAKE2S_256 },
        { CF_DIGEST("SHAKE128"), GCRY_MD_SHAKE128 },
        { CF_DIGEST("SHAKE256"), GCRY_MD_SHAKE256 },
        { CF_DIGEST("SHA3-224"), GCRY_MD_SHA3_224 },
        { CF_DIGEST("SHA3-256"), GCRY_MD_SHA3_256 },
        { CF_DIGEST("SHA3-384"), GCRY_MD_SHA3_384 },
        { CF_DIGEST("SHA3-512"), GCRY_MD_SHA3_512 },
        { CF_DIGEST("STREEBOG-256"), GCRY_MD_STRIBOG256 },
        { CF_DIGEST("STREEBOG-512"), GCRY_MD_STRIBOG512 },
    };

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;
    util::Multipart parts;

    gcry_md_hd_t h;
    bool hOpen = false;
    int digestType = -1;

    /* Initialize */
    {
        CF_CHECK_NE(LUT.find(op.digestType.Get()), LUT.end());
        digestType = LUT.at(op.digestType.Get());

        bool useSecMem = false;
        try {
            useSecMem = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        CF_CHECK_EQ(gcry_md_open(&h, digestType, useSecMem ? GCRY_MD_FLAG_SECURE : 0), GPG_ERR_NO_ERROR);
        hOpen = true;

        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        bool usePutc = false;
        try {
            usePutc = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( usePutc == true ) {
            for (size_t i = 0; i < part.second; i++) {
                /* gcry_md_pubc does not return a value */
                gcry_md_putc(h, part.first[i]);
            }
        } else {
            /* gcry_md_write does not return a value */
            gcry_md_write(h, part.first, part.second);
        }
    }

    /* Finalize */
    {

        bool callFinal = false;
        try {
            callFinal = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( callFinal == true ) {
            /* gcry_md_final does not return a value */
            gcry_md_final(h);
        }

        switch ( op.digestType.Get() ) {
            case    CF_DIGEST("SHAKE128"):
                {
                    /* Same output size as OpenSSL with SHAKE128 by default */
                    uint8_t out[16];
                    CF_CHECK_EQ(gcry_md_extract(h, digestType, out, sizeof(out)), GPG_ERR_NO_ERROR);
                    ret = component::Digest(out, sizeof(out));
                }
                break;
            case    CF_DIGEST("SHAKE256"):
                {
                    /* Same output size as OpenSSL with SHAKE256 by default */
                    uint8_t out[32];
                    CF_CHECK_EQ(gcry_md_extract(h, digestType, out, sizeof(out)), GPG_ERR_NO_ERROR);
                    ret = component::Digest(out, sizeof(out));
                }
                break;
            default:
                {
                    auto out = gcry_md_read(h, digestType);
                    CF_CHECK_NE(out, nullptr);
                    ret = component::Digest(out, gcry_md_get_algo_dlen(digestType));
                }
                break;
        }
    }

end:
    if ( hOpen == true ) {
        gcry_md_close(h);
    }

    return ret;
}

std::optional<component::MAC> libgcrypt::OpHMAC(operation::HMAC& op) {
    static const std::map<uint64_t, int> LUT = {
        { CF_DIGEST("SHA1"), GCRY_MAC_HMAC_SHA1 },
        { CF_DIGEST("SHA224"), GCRY_MAC_HMAC_SHA224 },
        { CF_DIGEST("SHA256"), GCRY_MAC_HMAC_SHA256 },
        { CF_DIGEST("SHA384"), GCRY_MAC_HMAC_SHA384 },
        { CF_DIGEST("SHA512"), GCRY_MAC_HMAC_SHA512 },
        { CF_DIGEST("MD4"), GCRY_MAC_HMAC_MD4 },
        { CF_DIGEST("MD5"), GCRY_MAC_HMAC_MD5 },
        { CF_DIGEST("RIPEMD160"), GCRY_MAC_HMAC_RMD160 },
        { CF_DIGEST("WHIRLPOOL"), GCRY_MAC_HMAC_WHIRLPOOL },
        { CF_DIGEST("SHA3-224"), GCRY_MAC_HMAC_SHA3_224 },
        { CF_DIGEST("SHA3-256"), GCRY_MAC_HMAC_SHA3_256 },
        { CF_DIGEST("SHA3-384"), GCRY_MAC_HMAC_SHA3_384 },
        { CF_DIGEST("SHA3-512"), GCRY_MAC_HMAC_SHA3_512 },
        { CF_DIGEST("STREEBOG-256"), GCRY_MAC_HMAC_STRIBOG256 },
        { CF_DIGEST("STREEBOG-512"), GCRY_MAC_HMAC_STRIBOG512 },
    };

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;
    util::Multipart parts;

    gcry_mac_hd_t h;
    bool hOpen = false;
    int hmacType = -1;

    /* Initialize */
    {
        CF_CHECK_NE(LUT.find(op.digestType.Get()), LUT.end());
        hmacType = LUT.at(op.digestType.Get());

        bool useSecMem = false;
        try {
            useSecMem = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        CF_CHECK_EQ(gcry_mac_open(&h, hmacType, useSecMem ? GCRY_MD_FLAG_SECURE : 0, nullptr), GPG_ERR_NO_ERROR);
        hOpen = true;

        CF_CHECK_EQ(gcry_mac_setkey(h, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), GPG_ERR_NO_ERROR);

        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(gcry_mac_write(h, part.first, part.second), GPG_ERR_NO_ERROR);
    }

    /* Finalize */
    {
        size_t length = gcry_mac_get_algo_maclen(hmacType);
        CF_CHECK_GTE(length, 0);
        uint8_t out[length];
        CF_CHECK_EQ(gcry_mac_read(h, out, &length), GPG_ERR_NO_ERROR);
        ret = component::Digest(out, length);
    }

end:
    if ( hOpen == true ) {
        gcry_mac_close(h);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
