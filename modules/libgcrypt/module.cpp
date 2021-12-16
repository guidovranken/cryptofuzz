#include "module.h"
#include <cryptofuzz/util.h>
#include <gcrypt.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

libgcrypt::libgcrypt(void) :
    Module("libgcrypt") {
    if ( !gcry_check_version(GCRYPT_VERSION) ) {
        abort();
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN, 0);
}

namespace libgcrypt_detail {

    std::optional<int> DigestIDToID(const uint64_t digestType) {
        static const std::map<uint64_t, int> LUT = {
            { CF_DIGEST("BLAKE2B160"), GCRY_MD_BLAKE2B_160 },
            { CF_DIGEST("BLAKE2B256"), GCRY_MD_BLAKE2B_256 },
            { CF_DIGEST("BLAKE2B384"), GCRY_MD_BLAKE2B_384 },
            { CF_DIGEST("BLAKE2B512"), GCRY_MD_BLAKE2B_512 },
            { CF_DIGEST("BLAKE2S128"), GCRY_MD_BLAKE2S_128 },
            { CF_DIGEST("BLAKE2S160"), GCRY_MD_BLAKE2S_160 },
            { CF_DIGEST("BLAKE2S224"), GCRY_MD_BLAKE2S_224 },
            { CF_DIGEST("BLAKE2S256"), GCRY_MD_BLAKE2S_256 },
            { CF_DIGEST("CRC24-RFC2440"), GCRY_MD_CRC24_RFC2440 },
            { CF_DIGEST("CRC32"), GCRY_MD_CRC32 },
            { CF_DIGEST("CRC32-RFC1510"), GCRY_MD_CRC32_RFC1510 },
            { CF_DIGEST("CRC32-RFC2440"), GCRY_MD_CRC24_RFC2440 },
            { CF_DIGEST("GOST-R-34.11-94"), GCRY_MD_GOSTR3411_CP },
            { CF_DIGEST("MD4"), GCRY_MD_MD4 },
            { CF_DIGEST("MD5"), GCRY_MD_MD5 },
            { CF_DIGEST("RIPEMD160"), GCRY_MD_RMD160 },
            { CF_DIGEST("SHA1"), GCRY_MD_SHA1 },
            { CF_DIGEST("SHA224"), GCRY_MD_SHA224 },
            { CF_DIGEST("SHA256"), GCRY_MD_SHA256 },
            { CF_DIGEST("SHA3-224"), GCRY_MD_SHA3_224 },
            { CF_DIGEST("SHA3-256"), GCRY_MD_SHA3_256 },
            { CF_DIGEST("SHA3-384"), GCRY_MD_SHA3_384 },
            { CF_DIGEST("SHA3-512"), GCRY_MD_SHA3_512 },
            { CF_DIGEST("SHA384"), GCRY_MD_SHA384 },
            { CF_DIGEST("SHA512"), GCRY_MD_SHA512 },
            { CF_DIGEST("SHA512-224"), GCRY_MD_SHA512_224 },
            { CF_DIGEST("SHA512-256"), GCRY_MD_SHA512_256 },
            { CF_DIGEST("SHAKE128"), GCRY_MD_SHAKE128 },
            { CF_DIGEST("SHAKE256"), GCRY_MD_SHAKE256 },
            { CF_DIGEST("SM3"), GCRY_MD_SM3 },
            { CF_DIGEST("STREEBOG-256"), GCRY_MD_STRIBOG256 },
            { CF_DIGEST("STREEBOG-512"), GCRY_MD_STRIBOG512 },
            { CF_DIGEST("TIGER"), GCRY_MD_TIGER1 },
            { CF_DIGEST("WHIRLPOOL"), GCRY_MD_WHIRLPOOL },
        };

        std::optional<int> ret = std::nullopt;

        CF_CHECK_NE(LUT.find(digestType), LUT.end());
        ret = LUT.at(digestType);
end:
        return ret;
    }

    class MD_Handle {
        private:
            gcry_md_hd_t h;
            bool hOpen = false;
            Datasource& ds;
        public:
            MD_Handle(Datasource& ds) :
                ds(ds)
            { }
            ~MD_Handle() {
                if ( hOpen == true ) {
                    /* noret */ gcry_md_close(h);
                }
            }
            bool Open(const int digestType) {
                bool ret = false;

                bool useSecMem = false;
                try {
                    useSecMem = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                CF_CHECK_EQ(gcry_md_open(&h, digestType, useSecMem ? GCRY_MD_FLAG_SECURE : 0), GPG_ERR_NO_ERROR);

                hOpen = true;

                ret = true;
end:
                return ret;
            }
            gcry_md_hd_t Get(void) {
                bool copy = false;
                try {
                    copy = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( copy == true ) {
                    gcry_md_hd_t h2;
                    if ( gcry_md_copy(&h2, h) == GPG_ERR_NO_ERROR ) {
                        /* noret */ gcry_md_close(h);
                        h = h2;
                    }
                }
                return h;
            }
            void Write(const uint8_t* data, const size_t size) {
                bool usePutc = false;

                /* gcry_md_putc is too slow for large amounts of data */
                if ( size < 1000 ) {
                    try {
                        usePutc = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( usePutc == true ) {
                    for (size_t i = 0; i < size; i++) {
                        /* noret */ gcry_md_putc(Get(), data[i]);
                    }
                } else {
                    /* noret */ gcry_md_write(Get(), data, size);
                }
            }
            void Final(void) {
                bool callFinal = false;
                try {
                    callFinal = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( callFinal == true ) {
                    /* gcry_md_final does not return a value */
                    gcry_md_final(Get());
                }
            }
    };

    template <class HandleType>
    class Handle {
        protected:
            HandleType h;
            bool hOpen = false;
            Datasource& ds;
            virtual bool open(const int digestType, const bool useSecMem) = 0;
            virtual void copy(void) = 0;
            virtual void _close(void) = 0;
            virtual bool write(const uint8_t* data, const size_t size) = 0;
            virtual void _final(void) = 0;
        public:
            Handle(Datasource& ds) :
                ds(ds)
            { }
            ~Handle() {
            }
            bool Open(const int digestType) {
                bool ret = false;

                bool useSecMem = false;
                try {
                    useSecMem = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                CF_CHECK_TRUE(open(digestType, useSecMem));

                hOpen = true;

                ret = true;
end:
                return ret;
            }
            HandleType Get(void) {
                bool copy = false;
                try {
                    copy = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( copy == true ) {
                    this->copy();
                }
                return h;
            }
            bool Write(const uint8_t* data, const size_t size) {
                return write(data, size);
            }
            void Final(void) {
                bool callFinal = false;
                try {
                    callFinal = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( callFinal == true ) {
                    _final();
                }
            }
            void WriteRandom(void) {
                /* Write a buffer of random size a random amount of times.
                 *
                 * This is to catch the buffer overflow in libgcrypt 1.90.0:
                 *
                 * https://dev.gnupg.org/rC512c0c75276949f13b6373b5c04f7065af750b08
                 */
                try {
                    while ( ds.Get<bool>() ) {
                        const auto size = ds.Get<uint16_t>();

                        std::vector<uint8_t> data(size);

                        /* ignore result */ Write(data.data(), size);
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            }
    };

    class DigestHandle : public Handle<gcry_md_hd_t> {
        private:
            bool open(const int digestType, const bool useSecMem) override {
                return gcry_md_open(&h, digestType, useSecMem ? GCRY_MD_FLAG_SECURE : 0) == GPG_ERR_NO_ERROR;
            }
            void copy(void) override {
                gcry_md_hd_t h2;
                if ( gcry_md_copy(&h2, h) == GPG_ERR_NO_ERROR ) {
                    /* noret */ gcry_md_close(h);
                    h = h2;
                }
            }
            void _close(void) override {
                /* noret */ gcry_md_close(h);
            }
            bool write(const uint8_t* data, const size_t size) override {
                bool usePutc = false;

                /* gcry_md_putc is too slow for large amounts of data */
                if ( size < 1000 ) {
                    try {
                        usePutc = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( usePutc == true ) {
                    for (size_t i = 0; i < size; i++) {
                        /* noret */ gcry_md_putc(Get(), data[i]);
                    }
                } else {
                    /* noret */ gcry_md_write(Get(), data, size);
                }

                return true;
            }
            void _final(void) override {
                /* noret */ gcry_md_final(Get());
            }
        public:
            DigestHandle(Datasource& ds) :
                Handle<gcry_md_hd_t>(ds)
            { }
            ~DigestHandle() {
                if ( hOpen == true ) {
                    /* noret */ gcry_md_close(h);
                }
            }
    };

    class MACHandle : public Handle<gcry_mac_hd_t> {
        private:
            bool open(const int digestType, const bool useSecMem) override {
                return gcry_mac_open(&h, digestType, useSecMem ? GCRY_CIPHER_SECURE : 0, nullptr) == GPG_ERR_NO_ERROR;
            }
            void copy(void) override {
                /* There is no copy function for MAC */
            }
            void _close(void) override {
                /* noret */ gcry_mac_close(h);
            }
            bool write(const uint8_t* data, const size_t size) override {
                return gcry_mac_write(Get(), data, size) == GPG_ERR_NO_ERROR;
            }
            void _final(void) override {
                /* There is no final function for MAC */
            }
        public:
            MACHandle(Datasource& ds) :
                Handle<gcry_mac_hd_t>(ds)
            { }
            ~MACHandle() {
                if ( hOpen == true ) {
                    /* noret */ gcry_mac_close(h);
                }
            }
    };

    std::optional<component::MAC> MAC(
            fuzzing::datasource::Datasource& ds,
            const int macType,
            const Buffer& cleartext,
            const component::SymmetricCipher& cipher) {
        std::optional<component::MAC> ret = std::nullopt;
        util::Multipart parts;

        libgcrypt_detail::MACHandle h(ds);

        /* Initialize */
        {
            CF_CHECK_TRUE(h.Open(macType));

            CF_CHECK_EQ(gcry_mac_setkey(h.Get(), cipher.key.GetPtr(), cipher.key.GetSize()), GPG_ERR_NO_ERROR);

            parts = util::ToParts(ds, cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_TRUE(h.Write(part.first, part.second));
        }

        /* Finalize */
        {
            size_t length = gcry_mac_get_algo_maclen(macType);
            CF_CHECK_GTE(length, 0);
            uint8_t out[length];
            CF_CHECK_EQ(gcry_mac_read(h.Get(), out, &length), GPG_ERR_NO_ERROR);
            ret = component::MAC(out, length);

            /* noret */ h.WriteRandom();
        }

end:
        return ret;
    }

} /* namespace libgcrypt_detail */

std::optional<component::Digest> libgcrypt::OpDigest(operation::Digest& op) {

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;
    util::Multipart parts;

    libgcrypt_detail::DigestHandle h(ds);
    std::optional<int> digestType = std::nullopt;

    /* Initialize */
    {
        CF_CHECK_NE(digestType = libgcrypt_detail::DigestIDToID(op.digestType.Get()), std::nullopt);

        CF_CHECK_TRUE(h.Open(*digestType));

        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_TRUE(h.Write(part.first, part.second));
    }

    /* Finalize */
    {
        /* noret */ h.Final();

        switch ( op.digestType.Get() ) {
            case    CF_DIGEST("SHAKE128"):
                {
                    /* Same output size as OpenSSL with SHAKE128 by default */
                    uint8_t out[16];
                    CF_CHECK_EQ(gcry_md_extract(h.Get(), *digestType, out, sizeof(out)), GPG_ERR_NO_ERROR);
                    ret = component::Digest(out, sizeof(out));
                }
                break;
            case    CF_DIGEST("SHAKE256"):
                {
                    /* Same output size as OpenSSL with SHAKE256 by default */
                    uint8_t out[32];
                    CF_CHECK_EQ(gcry_md_extract(h.Get(), *digestType, out, sizeof(out)), GPG_ERR_NO_ERROR);
                    ret = component::Digest(out, sizeof(out));
                }
                break;
            default:
                {
                    auto out = gcry_md_read(h.Get(), *digestType);
                    CF_CHECK_NE(out, nullptr);
                    ret = component::Digest(out, gcry_md_get_algo_dlen(*digestType));
                }
                break;
        }

        /* noret */ h.WriteRandom();
    }

end:
    return ret;
}

std::optional<component::MAC> libgcrypt::OpHMAC(operation::HMAC& op) {
    int macType = -1;

    static const std::map<uint64_t, int> LUT = {
        { CF_DIGEST("BLAKE2B160"), GCRY_MAC_HMAC_BLAKE2B_160 },
        { CF_DIGEST("BLAKE2B256"), GCRY_MAC_HMAC_BLAKE2B_256 },
        { CF_DIGEST("BLAKE2B384"), GCRY_MAC_HMAC_BLAKE2B_384 },
        { CF_DIGEST("BLAKE2B512"), GCRY_MAC_HMAC_BLAKE2B_512 },
        { CF_DIGEST("BLAKE2S128"), GCRY_MAC_HMAC_BLAKE2S_128 },
        { CF_DIGEST("BLAKE2S160"), GCRY_MAC_HMAC_BLAKE2S_160 },
        { CF_DIGEST("BLAKE2S224"), GCRY_MAC_HMAC_BLAKE2S_224 },
        { CF_DIGEST("BLAKE2S256"), GCRY_MAC_HMAC_BLAKE2S_256 },
        { CF_DIGEST("GOST-R-34.11-94"), GCRY_MAC_HMAC_GOSTR3411_CP },
        { CF_DIGEST("MD4"), GCRY_MAC_HMAC_MD4 },
        { CF_DIGEST("MD5"), GCRY_MAC_HMAC_MD5 },
        { CF_DIGEST("RIPEMD160"), GCRY_MAC_HMAC_RMD160 },
        { CF_DIGEST("SHA1"), GCRY_MAC_HMAC_SHA1 },
        { CF_DIGEST("SHA224"), GCRY_MAC_HMAC_SHA224 },
        { CF_DIGEST("SHA256"), GCRY_MAC_HMAC_SHA256 },
        { CF_DIGEST("SHA3-224"), GCRY_MAC_HMAC_SHA3_224 },
        { CF_DIGEST("SHA3-256"), GCRY_MAC_HMAC_SHA3_256 },
        { CF_DIGEST("SHA3-384"), GCRY_MAC_HMAC_SHA3_384 },
        { CF_DIGEST("SHA3-512"), GCRY_MAC_HMAC_SHA3_512 },
        { CF_DIGEST("SHA384"), GCRY_MAC_HMAC_SHA384 },
        { CF_DIGEST("SHA512"), GCRY_MAC_HMAC_SHA512 },
        { CF_DIGEST("SHA512-224"), GCRY_MAC_HMAC_SHA512_224 },
        { CF_DIGEST("SHA512-256"), GCRY_MAC_HMAC_SHA512_256 },
        { CF_DIGEST("SM3"), GCRY_MAC_HMAC_SM3 },
        { CF_DIGEST("STREEBOG-256"), GCRY_MAC_HMAC_STRIBOG256 },
        { CF_DIGEST("STREEBOG-512"), GCRY_MAC_HMAC_STRIBOG512 },
        { CF_DIGEST("TIGER"), GCRY_MAC_HMAC_TIGER1 },
        { CF_DIGEST("WHIRLPOOL"), GCRY_MAC_HMAC_WHIRLPOOL },
    };

    CF_CHECK_NE(LUT.find(op.digestType.Get()), LUT.end());
    macType = LUT.at(op.digestType.Get());

    {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        return libgcrypt_detail::MAC(ds, macType, op.cleartext, op.cipher);
    }

end:
    return std::nullopt;
}

std::optional<component::MAC> libgcrypt::OpCMAC(operation::CMAC& op) {
    int macType = -1;

    static const std::map<uint64_t, int> LUT = {
        { CF_CIPHER("AES_128_CBC"), GCRY_MAC_CMAC_AES },
        { CF_CIPHER("AES_192_CBC"), GCRY_MAC_CMAC_AES },
        { CF_CIPHER("AES_256_CBC"), GCRY_MAC_CMAC_AES },
        { CF_CIPHER("CAMELLIA_128_CBC"), GCRY_MAC_CMAC_CAMELLIA },
        { CF_CIPHER("CAMELLIA_192_CBC"), GCRY_MAC_CMAC_CAMELLIA },
        { CF_CIPHER("CAMELLIA_256_CBC"), GCRY_MAC_CMAC_CAMELLIA },
        { CF_CIPHER("CAST5_CBC"), GCRY_MAC_CMAC_CAST5 },
        { CF_CIPHER("BLOWFISH_CBC"), GCRY_MAC_CMAC_BLOWFISH },
        { CF_CIPHER("TWOFISH"), GCRY_MAC_CMAC_TWOFISH },
        { CF_CIPHER("TWOFISH_CBC"), GCRY_MAC_CMAC_TWOFISH },
        { CF_CIPHER("SERPENT"), GCRY_MAC_CMAC_SERPENT },
        { CF_CIPHER("SERPENT_CBC"), GCRY_MAC_CMAC_SERPENT },
        { CF_CIPHER("SEED_CBC"), GCRY_MAC_CMAC_SEED },
        { CF_CIPHER("IDEA_CBC"), GCRY_MAC_CMAC_IDEA },
        { CF_CIPHER("SM4_CBC"), GCRY_MAC_CMAC_SM4 },
        { CF_CIPHER("RC2_40_CBC"), GCRY_MAC_CMAC_RFC2268 },
        { CF_CIPHER("RC2_64_CBC"), GCRY_MAC_CMAC_RFC2268 },
        { CF_CIPHER("RC2_CBC"), GCRY_MAC_CMAC_RFC2268 },
        { CF_CIPHER("GOST-28147-89"), GCRY_MAC_CMAC_GOST28147 },
        { CF_CIPHER("GOST-28147-89_CBC"), GCRY_MAC_CMAC_GOST28147 },
    };

    CF_CHECK_NE(LUT.find(op.cipher.cipherType.Get()), LUT.end());
    macType = LUT.at(op.cipher.cipherType.Get());

    {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        return libgcrypt_detail::MAC(ds, macType, op.cleartext, op.cipher);
    }

end:
    return std::nullopt;
}

namespace libgcrypt_detail {
    static const std::map<uint64_t, std::pair<int, int>> SymmetricCipherLUT = {
        { CF_CIPHER("AES_128_CBC"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("AES_128_CCM"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM} },
        { CF_CIPHER("AES_128_CFB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_128_CTR"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("AES_128_ECB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_128_GCM"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM} },
        { CF_CIPHER("AES_128_OFB"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_128_XTS"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS} },
        { CF_CIPHER("AES_192_CBC"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("AES_192_CCM"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM} },
        { CF_CIPHER("AES_192_CFB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_192_CTR"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("AES_192_ECB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_192_GCM"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM} },
        { CF_CIPHER("AES_192_OFB"), {GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_256_CBC"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("AES_256_CCM"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM} },
        { CF_CIPHER("AES_256_CFB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("AES_256_CTR"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("AES_256_ECB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("AES_256_GCM"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM} },
        { CF_CIPHER("AES_256_OFB"), {GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("AES_256_XTS"), {GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS} },
        { CF_CIPHER("BF_CBC"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("BF_CFB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("BF_ECB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("BF_OFB"), {GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_128_CBC"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("CAMELLIA_128_CFB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_128_CTR"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("CAMELLIA_128_ECB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_128_OFB"), {GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_192_CBC"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("CAMELLIA_192_CFB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_192_CTR"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("CAMELLIA_192_ECB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_192_OFB"), {GCRY_CIPHER_CAMELLIA192, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAMELLIA_256_CBC"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("CAMELLIA_256_CFB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAMELLIA_256_CTR"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_CTR} },
        { CF_CIPHER("CAMELLIA_256_ECB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAMELLIA_256_OFB"), {GCRY_CIPHER_CAMELLIA256, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CAST5_CBC"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("CAST5_CFB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("CAST5_ECB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("CAST5_OFB"), {GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("CHACHA20"), {GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM} },
        { CF_CIPHER("DES_CBC"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("DES_CFB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("DES_ECB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("DES_EDE3_CFB"), {GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("DES_EDE3_OFB"), {GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("DES_OFB"), {GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("IDEA_CBC"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_CBC} },
        { CF_CIPHER("IDEA_CFB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("IDEA_ECB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("IDEA_OFB"), {GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("RC2_CFB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("RC2_ECB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("RC2_OFB"), {GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("SEED_CFB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("SEED_ECB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("SEED_OFB"), {GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OFB} },
        { CF_CIPHER("SM4_CFB"), {GCRY_CIPHER_SM4, GCRY_CIPHER_MODE_CFB} },
        { CF_CIPHER("SM4_ECB"), {GCRY_CIPHER_SM4, GCRY_CIPHER_MODE_ECB} },
        { CF_CIPHER("SM4_OFB"), {GCRY_CIPHER_SM4, GCRY_CIPHER_MODE_OFB} },
    };

    std::optional<size_t> Blocksize(const uint64_t cipher) {
        std::optional<size_t> ret = std::nullopt;

        switch ( cipher ) {
            case    CF_CIPHER("AES_128_CBC"):
            case    CF_CIPHER("AES_192_CBC"):
            case    CF_CIPHER("AES_256_CBC"):
            case    CF_CIPHER("CAMELLIA_128_CBC"):
            case    CF_CIPHER("CAMELLIA_192_CBC"):
            case    CF_CIPHER("CAMELLIA_256_CBC"):
                ret = 16;
                break;
            case    CF_CIPHER("BF_CBC"):
            case    CF_CIPHER("CAST5_CBC"):
            case    CF_CIPHER("DES_CBC"):
            case    CF_CIPHER("IDEA_CBC"):
                ret = 8;
                break;
        }

        return ret;
    }

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

                /* CFB is broken */
                //CF_CHECK_EQ(repository::IsCFB(cipher.cipherType.Get()), false);

                const auto cipherModePair = SymmetricCipherLUT.at(cipher.cipherType.Get());

                CF_CHECK_EQ(gcry_cipher_get_algo_keylen(cipherModePair.first), cipher.key.GetSize());
                if ( cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
                    CF_CHECK_EQ(12, cipher.iv.GetSize());
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
                if ( cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
                    CF_CHECK_EQ(gcry_cipher_setiv(h, cipher.iv.GetPtr(), cipher.iv.GetSize()), GPG_ERR_NO_ERROR);
                } else if ( repository::IsCTR(cipher.cipherType.Get()) ) {
                    CF_CHECK_EQ(gcry_cipher_setctr(h, cipher.iv.GetPtr(), cipher.iv.GetSize()), GPG_ERR_NO_ERROR);
                } else {
                    CF_CHECK_EQ(gcry_cipher_setiv(h, cipher.iv.GetPtr(), cipher.iv.GetSize()), GPG_ERR_NO_ERROR);
                }

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

        template <bool Encrypt>
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

                if ( Encrypt == true ) {
                    CF_CHECK_EQ(gcry_cipher_encrypt(h, out + outIdx, outputBufferSize - outIdx, part.first, part.second), GPG_ERR_NO_ERROR);
                } else {
                    CF_CHECK_EQ(gcry_cipher_decrypt(h, out + outIdx, outputBufferSize - outIdx, part.first, part.second), GPG_ERR_NO_ERROR);
                }
                outIdx += part.second;
            }

            ret = outIdx;

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
                CF_CHECK_EQ(op.tagSize, std::nullopt);
                CF_CHECK_EQ(op.aad, std::nullopt);

                std::vector<uint8_t> cleartext = op.cleartext.Get();
                if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
                    auto blockSize = Blocksize(op.cipher.cipherType.Get());
                    CF_CHECK_NE(blockSize, std::nullopt);

                    cleartext = util::Pkcs7Pad(op.cleartext.Get(), *blockSize);
                }
                CF_CHECK_EQ(initialize(op.cipher, cleartext.data(), cleartext.size()), true);
                std::optional<size_t> outputSize = process<true>();
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
                CF_CHECK_EQ(op.tag, std::nullopt);
                CF_CHECK_EQ(op.aad, std::nullopt);

                CF_CHECK_EQ(initialize(op.cipher, op.ciphertext.GetPtr(), op.ciphertext.GetSize()), true);
                std::optional<size_t> outputSize = process<false>();
                CF_CHECK_NE(outputSize, std::nullopt);

                if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
                    auto blockSize = Blocksize(op.cipher.cipherType.Get());
                    CF_CHECK_NE(blockSize, std::nullopt);

                    const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + *outputSize), *blockSize);
                    CF_CHECK_NE(unpaddedCleartext, std::nullopt);

                    ret = component::Cleartext(Buffer(*unpaddedCleartext));
                } else {
                    ret = component::Cleartext(out, *outputSize);
                }
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

std::optional<component::Key> libgcrypt::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    /* Block size fixed at 8 */
    CF_CHECK_EQ(op.r, 8);

    CF_CHECK_EQ(gcry_kdf_derive(
                op.password.GetPtr(),
                op.password.GetSize(),
                GCRY_KDF_SCRYPT,
                op.N,
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.p,
                outSize,
                out), GPG_ERR_NO_ERROR);

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> libgcrypt::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    std::optional<int> digestType = std::nullopt;
    CF_CHECK_NE(digestType = libgcrypt_detail::DigestIDToID(op.digestType.Get()), std::nullopt);
    CF_CHECK_EQ(gcry_kdf_derive(
                op.password.GetPtr(),
                op.password.GetSize(),
                GCRY_KDF_PBKDF2,
                *digestType,
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                outSize,
                out), GPG_ERR_NO_ERROR);

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
}

namespace libgcrypt_detail {
    std::optional<std::string> toCurveString(const component::CurveType& curveType) {
        static const std::map<uint64_t, std::string> LUT = {
#if 0
            { CF_ECC_CURVE(""), "Curve25519" },
            { CF_ECC_CURVE(""), "Ed25519" },
            { CF_ECC_CURVE(""), "GOST2001-CryptoPro-A" },
            { CF_ECC_CURVE(""), "GOST2001-CryptoPro-B" },
            { CF_ECC_CURVE(""), "GOST2001-CryptoPro-C" },
            { CF_ECC_CURVE(""), "GOST2001-test" },
            { CF_ECC_CURVE(""), "NIST P-192" },
            { CF_ECC_CURVE(""), "NIST P-224" },
            { CF_ECC_CURVE(""), "NIST P-256" },
            { CF_ECC_CURVE(""), "NIST P-384" },
            { CF_ECC_CURVE(""), "NIST P-521" },
            { CF_ECC_CURVE(""), "X448" },
#endif
            { CF_ECC_CURVE("gost_256A"), "GOST2012-256-tc26-A" },
            { CF_ECC_CURVE("gost_512A"), "GOST2012-512-tc26-A" },
            { CF_ECC_CURVE("brainpool160r1"), "brainpoolP160r1" },
            { CF_ECC_CURVE("brainpool192r1"), "brainpoolP192r1" },
            { CF_ECC_CURVE("brainpool224r1"), "brainpoolP224r1" },
            { CF_ECC_CURVE("brainpool256r1"), "brainpoolP256r1" },
            { CF_ECC_CURVE("brainpool320r1"), "brainpoolP320r1" },
            { CF_ECC_CURVE("brainpool384r1"), "brainpoolP384r1" },
            { CF_ECC_CURVE("brainpool512r1"), "brainpoolP512r1" },
            { CF_ECC_CURVE("secp256k1"), "secp256k1" },
            { CF_ECC_CURVE("sm2p256v1"), "sm2p256v1" },
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(curveType.Get());
    }
} /* namespace libgcrypt_detail */

std::optional<component::ECC_PublicKey> libgcrypt::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::string> curveStr = std::nullopt;

    gcry_ctx_t ctx = nullptr;
    gcry_mpi_point_t Q = nullptr;
    gcry_mpi_point_t G = nullptr;

    libgcrypt_bignum::Bignum priv;
    libgcrypt_bignum::Bignum x;
    libgcrypt_bignum::Bignum y;
    CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
    CF_CHECK_EQ(x.Set("0"), true);
    CF_CHECK_EQ(y.Set("0"), true);

    /* Initialize */
    {
        CF_CHECK_NE(curveStr = libgcrypt_detail::toCurveString(op.curveType), std::nullopt);
        CF_CHECK_EQ(gcry_mpi_ec_new(&ctx, nullptr, curveStr->c_str()), 0);
    }

    /* Process */
    {
        CF_CHECK_NE(G = gcry_mpi_ec_get_point("g", ctx, 1), nullptr);
        CF_CHECK_NE(Q = gcry_mpi_point_new(0), nullptr);
        /* noret */ gcry_mpi_ec_mul(Q, priv.GetPtr(), G, ctx);
    }

    /* Finalize */
    {
        CF_CHECK_EQ(gcry_mpi_ec_get_affine(x.GetPtr(), y.GetPtr(), Q, ctx), 0);

        std::optional<std::string> x_str;
        std::optional<std::string> y_str;

        CF_CHECK_NE(x_str = x.ToString(), std::nullopt);
        CF_CHECK_NE(y_str = y.ToString(), std::nullopt);

        ret = { *x_str, *y_str };
    }

end:
    gcry_ctx_release(ctx);
    gcry_mpi_point_release(Q);
    gcry_mpi_point_release(G);

    return ret;
}

std::optional<bool> libgcrypt::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::string> curveStr = std::nullopt;
    gcry_sexp_t sig_sexp, data_sexp, pub_sexp;
    bool sig_sexp_set = false;
    bool data_sexp_set = false;
    bool pub_sexp_set = false;

    CF_CHECK_NE(curveStr = libgcrypt_detail::toCurveString(op.curveType), std::nullopt);

    {
        const auto numBits = cryptofuzz::repository::ECC_CurveToBits(op.curveType.Get());
        CF_CHECK_NE(numBits, std::nullopt);
        const size_t numBytes = (*numBits + 7) / 8;

        CF_CHECK_EQ(op.cleartext.GetSize(), numBytes);
    }

    CF_CHECK_TRUE(op.digestType.Is(CF_DIGEST("NULL")));

    /* Set signature */
    {
        libgcrypt_bignum::Bignum r, s;
        CF_CHECK_EQ(r.Set(op.signature.signature.first.ToString(ds)), true);
        CF_CHECK_EQ(s.Set(op.signature.signature.second.ToString(ds)), true);
        CF_CHECK_EQ(gcry_sexp_build(&sig_sexp, nullptr, "(sig-val (ecdsa (r %M) (s %M)))", r.GetPtr(), s.GetPtr()), GPG_ERR_NO_ERROR)
    }
    sig_sexp_set = true;

    /* Set data */
    if ( op.cleartext.GetSize() > 32 ) {
        CF_CHECK_EQ(gcry_sexp_build(&data_sexp, nullptr, "(data (flags raw ) (value %b))", 32, op.cleartext.GetPtr() + op.cleartext.GetSize() - 32), GPG_ERR_NO_ERROR);
    } else {
        CF_CHECK_EQ(gcry_sexp_build(&data_sexp, nullptr, "(data (flags raw ) (value %b))", op.cleartext.GetSize(), op.cleartext.GetPtr()), GPG_ERR_NO_ERROR);
    }
    data_sexp_set = true;

    /* Set pubkey */

    {
        std::optional<std::vector<uint8_t>> pub_x, pub_y;
        CF_CHECK_NE(pub_x = util::DecToBin(op.signature.pub.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(pub_y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), 32), std::nullopt);

        std::vector<uint8_t> pub;

        pub.push_back(0x04);
        pub.insert(std::end(pub), std::begin(*pub_x), std::end(*pub_x));
        pub.insert(std::end(pub), std::begin(*pub_y), std::end(*pub_y));

        {
            std::string sexp_string;
            sexp_string += "(public-key (ecdsa (curve \"";
            sexp_string += *curveStr;
            sexp_string += "\") (q %b)))";

            CF_CHECK_EQ(gcry_sexp_build(&pub_sexp, NULL, sexp_string.c_str(), pub.size(), pub.data()), GPG_ERR_NO_ERROR);
            pub_sexp_set = true;
        }
    }

    ret = gcry_pk_verify(sig_sexp, data_sexp, pub_sexp) == GPG_ERR_NO_ERROR;

end:
    if ( sig_sexp_set ) {
        gcry_sexp_release(sig_sexp);
    }
    if ( data_sexp_set ) {
        gcry_sexp_release(data_sexp);
    }
    if ( pub_sexp_set ) {
        gcry_sexp_release(pub_sexp);
    }
    return ret;
}

std::optional<component::Bignum> libgcrypt::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<libgcrypt_bignum::Operation> opRunner = nullptr;

    libgcrypt_bignum::BignumCluster bn{ds,
        libgcrypt_bignum::Bignum(),
        libgcrypt_bignum::Bignum(),
        libgcrypt_bignum::Bignum(),
        libgcrypt_bignum::Bignum()
    };
    libgcrypt_bignum::Bignum res;

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Div>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<libgcrypt_bignum::ExpMod>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::GCD>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Cmp>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::Abs>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::Neg>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::LShift1>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::IsOne>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<libgcrypt_bignum::MulMod>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<libgcrypt_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<libgcrypt_bignum::SubMod>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Bit>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::ClearBit>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Mod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::Sqr>();
            break;
        case    CF_CALCOP("NumBits(A)"):
            opRunner = std::make_unique<libgcrypt_bignum::NumBits>();
            break;
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<libgcrypt_bignum::Exp>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}
} /* namespace module */
} /* namespace cryptofuzz */
