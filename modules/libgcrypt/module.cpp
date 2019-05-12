#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
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
        { CF_DIGEST("BLAKE2B160"), GCRY_MD_BLAKE2B_160 },
        { CF_DIGEST("BLAKE2B256"), GCRY_MD_BLAKE2B_256 },
        { CF_DIGEST("BLAKE2B384"), GCRY_MD_BLAKE2B_384 },
        { CF_DIGEST("BLAKE2B512"), GCRY_MD_BLAKE2B_512 },
        { CF_DIGEST("BLAKE2S128"), GCRY_MD_BLAKE2S_128 },
        { CF_DIGEST("BLAKE2S160"), GCRY_MD_BLAKE2S_160 },
        { CF_DIGEST("BLAKE2S224"), GCRY_MD_BLAKE2S_224 },
        { CF_DIGEST("BLAKE2S256"), GCRY_MD_BLAKE2S_256 },
        { CF_DIGEST("SHAKE128"), GCRY_MD_SHAKE128 },
        { CF_DIGEST("SHAKE256"), GCRY_MD_SHAKE256 },
        { CF_DIGEST("SHA3-224"), GCRY_MD_SHA3_224 },
        { CF_DIGEST("SHA3-256"), GCRY_MD_SHA3_256 },
        { CF_DIGEST("SHA3-384"), GCRY_MD_SHA3_384 },
        { CF_DIGEST("SHA3-512"), GCRY_MD_SHA3_512 },
        { CF_DIGEST("STREEBOG-256"), GCRY_MD_STRIBOG256 },
        { CF_DIGEST("STREEBOG-512"), GCRY_MD_STRIBOG512 },
        { CF_DIGEST("TIGER"), GCRY_MD_TIGER1 },
        { CF_DIGEST("GOST-R-34.11-94"), GCRY_MD_GOSTR3411_94 },

        /* All CRCs currently disabled due to somewhat difficult
         * to reproduce mismatches/garbage output.
         */
#if 0
        { CF_DIGEST("CRC32"), GCRY_MD_CRC32 },
        { CF_DIGEST("CRC32-RFC1510"), GCRY_MD_CRC32_RFC1510 },
        { CF_DIGEST("CRC32-RFC2440"), GCRY_MD_CRC24_RFC2440 },
#endif
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

namespace libgcrypt_detail {
    static const std::map<uint64_t, std::pair<int, int>> SymmetricCipherLUT = {
        { CF_CIPHER("IDEA_ECB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("DES_ECB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_128_ECB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_192_ECB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_256_ECB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("SEED_ECB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("BF_ECB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAST5_ECB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_128_ECB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_192_ECB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_256_ECB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("RC2_ECB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_ECB} },

        { CF_CIPHER("IDEA_CFB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("DES_CFB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_128_CFB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_192_CFB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_256_CFB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("SEED_CFB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("BF_CFB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAST5_CFB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_128_CFB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_192_CFB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_256_CFB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("RC2_CFB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("DES_EDE3_CFB"), {GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CFB} },

        { CF_CIPHER("AES_128_CTR"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("AES_192_CTR"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("AES_256_CTR"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR} },

        /* Wrong results */
#if 0
        { CF_CIPHER("CAMELLIA_128_CTR"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("CAMELLIA_192_CTR"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("CAMELLIA_256_CTR"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CTR} },
#endif

        { CF_CIPHER("AES_128_GCM"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM} },
        { CF_CIPHER("AES_192_GCM"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM} },
        { CF_CIPHER("AES_256_GCM"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM} },

        { CF_CIPHER("AES_128_CCM"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM} },
        { CF_CIPHER("AES_192_CCM"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM} },
        { CF_CIPHER("AES_256_CCM"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM} },

        { CF_CIPHER("AES_128_XTS"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS} },
        { CF_CIPHER("AES_256_XTS"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS} },

        { CF_CIPHER("IDEA_OFB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("DES_OFB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_128_OFB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_192_OFB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_256_OFB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("SEED_OFB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("BF_OFB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAST5_OFB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_128_OFB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_192_OFB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_256_OFB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("RC2_OFB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("DES_EDE3_OFB"), {GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OFB} },

        { CF_CIPHER("CHACHA20"), {GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM} },
    };
    class Crypt {
        private:

        Datasource ds;
        uint8_t* out = nullptr;
        bool hOpen = false;
        gcry_cipher_hd_t h;
        util::Multipart parts;
        size_t outputBufferSize;

        bool initialize(const component::SymmetricCipher& cipher, const uint8_t* input, const size_t inputSize) {
            bool ret = false;
            {
                CF_CHECK_NE(outputBufferSize, 0);
                CF_CHECK_NE(SymmetricCipherLUT.find(cipher.cipherType.Get()), SymmetricCipherLUT.end());

                /* CTR is broken */
                //CF_CHECK_EQ(repository::IsCTR(cipher.cipherType.Get()), false);

                /* CFB is broken */
                //CF_CHECK_EQ(repository::IsCFB(cipher.cipherType.Get()), false);

                const auto cipherModePair = SymmetricCipherLUT.at(cipher.cipherType.Get());

                CF_CHECK_EQ(gcry_cipher_get_algo_keylen(cipherModePair.first), cipher.key.GetSize());
                if ( cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
                    CF_CHECK_EQ(16, cipher.iv.GetSize());
                } else {
                    CF_CHECK_EQ(gcry_cipher_get_algo_blklen(cipherModePair.first), cipher.iv.GetSize());
                }

                bool useSecMem = false;
                try {
                    useSecMem = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                CF_CHECK_EQ(gcry_cipher_open(&h, cipherModePair.first, cipherModePair.second, useSecMem ? GCRY_CIPHER_SECURE : 0), GPG_ERR_NO_ERROR);
                hOpen = true;

                CF_CHECK_EQ(gcry_cipher_setkey(h, cipher.key.GetPtr(), cipher.key.GetSize()), GPG_ERR_NO_ERROR);
                CF_CHECK_EQ(gcry_cipher_setiv(h, cipher.iv.GetPtr(), cipher.iv.GetSize()), GPG_ERR_NO_ERROR);

                switch ( cipherModePair.second ) {
                    case GCRY_CIPHER_MODE_STREAM:
                    //case GCRY_CIPHER_MODE_OFB:
                    case GCRY_CIPHER_MODE_CTR:
                    case GCRY_CIPHER_MODE_CFB:
                    case GCRY_CIPHER_MODE_CCM:
                    case GCRY_CIPHER_MODE_GCM:
                    case GCRY_CIPHER_MODE_EAX:
                    case GCRY_CIPHER_MODE_POLY1305:
                        parts = util::CipherInputTransform(ds, cipher.cipherType, out, outputBufferSize, input, inputSize);
                        break;
                    default:
                        parts = { {input, inputSize} };
                }
            }

            ret = true;
        end:
            return ret;
        }

        std::optional<size_t> process(void) {
            std::optional<size_t> ret = std::nullopt;
            size_t outIdx = 0;
            size_t partNum = 0;

            for (const auto& part : parts) {
                if ( part.second == 0 ) {
                    continue;
                }
                CF_CHECK_GTE(outputBufferSize - outIdx, part.second);

                partNum++;
                if ( partNum == parts.size() ) {
                    CF_CHECK_EQ(gcry_cipher_final(h), GPG_ERR_NO_ERROR);
                }

                CF_CHECK_EQ(gcry_cipher_encrypt(h, out + outIdx, outputBufferSize - outIdx, part.first, part.second), GPG_ERR_NO_ERROR);
                outIdx += part.second;
            }

        end:
            return ret;
        }

        public:

        Crypt(operation::SymmetricEncrypt& op) :
            ds(op.modifier.GetPtr(), op.modifier.GetSize()),
            out(util::malloc(op.ciphertextSize)),
            outputBufferSize(op.ciphertextSize)
        { }

        Crypt(operation::SymmetricDecrypt& op) :
            ds(op.modifier.GetPtr(), op.modifier.GetSize()),
            out(util::malloc(op.cleartextSize)),
            outputBufferSize(op.cleartextSize)
        { }

        ~Crypt() {
            if ( hOpen == true ) {
                gcry_cipher_close(h);
            }
            if ( out != nullptr ) {
                util::free(out);
            }
        }

        std::optional<component::Ciphertext> Encrypt(operation::SymmetricEncrypt& op) {
            std::optional<component::Ciphertext> ret = std::nullopt;

            {
                /* AEAD currently not supported */
                CF_CHECK_NE(op.tagSize, std::nullopt);
                CF_CHECK_NE(op.aad, std::nullopt);

                CF_CHECK_EQ(initialize(op.cipher, op.cleartext.GetPtr(), op.cleartext.GetSize()), true);
                std::optional<size_t> outputSize = process();
                CF_CHECK_NE(outputSize, std::nullopt);

                ret = component::Ciphertext(Buffer(out, *outputSize));
            }
        end:
            return ret;
        }

        std::optional<component::Cleartext> Decrypt(operation::SymmetricDecrypt& op) {
            std::optional<component::Cleartext> ret = std::nullopt;

            {
                /* AEAD currently not supported */
                CF_CHECK_NE(op.tag, std::nullopt);
                CF_CHECK_NE(op.aad, std::nullopt);

                CF_CHECK_EQ(initialize(op.cipher, op.ciphertext.GetPtr(), op.ciphertext.GetSize()), true);
                std::optional<size_t> outputSize = process();
                CF_CHECK_NE(outputSize, std::nullopt);

                ret = component::Cleartext(out, *outputSize);
            }
        end:
            return ret;
        }

    };
} /* namespace libgcrypt_detail */

std::optional<component::Ciphertext> libgcrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    libgcrypt_detail::Crypt crypt(op);
    return crypt.Encrypt(op);
}

std::optional<component::Cleartext> libgcrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    libgcrypt_detail::Crypt crypt(op);
    return crypt.Decrypt(op);
}

} /* namespace module */
} /* namespace cryptofuzz */
