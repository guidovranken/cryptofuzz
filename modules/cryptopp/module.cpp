#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <cryptlib.h>
#include <sha.h>
#include <shake.h>
#include <ripemd.h>
#include <whrlpool.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <sm3.h>
#include <blake2.h>
#include <tiger.h>
#include <keccak.h>
#include <panama.h>
#include <crc.h>
#include <adler32.h>
#include <hmac.h>
#include <twofish.h>
#include <serpent.h>
#include <gost.h>
#include <aes.h>
#include <des.h>
#include <idea.h>
#include <seed.h>
#include <modes.h>
#include <sm4.h>
#include <rc2.h>
#include <blowfish.h>
#include <cast.h>
#include <camellia.h>
#include <aria.h>
#include <hkdf.h>
#include <scrypt.h>
#include <pwdbased.h>
#include <filters.h>
#include <memory>

namespace cryptofuzz {
namespace module {

CryptoPP::CryptoPP(void) :
    Module("Crypto++") { }

namespace CryptoPP_detail {
    template <template <typename> class Function, class Ret, class In>
    std::optional<Ret> InvokeByDigest(In& op) {
        switch ( op.digestType.Get() ) {
            case CF_DIGEST("SHA1"):
                return Function<::CryptoPP::SHA1>::Compute(op);
            case CF_DIGEST("SHA224"):
                return Function<::CryptoPP::SHA224>::Compute(op);
            case CF_DIGEST("SHA384"):
                return Function<::CryptoPP::SHA384>::Compute(op);
            case CF_DIGEST("SHA512"):
                return Function<::CryptoPP::SHA512>::Compute(op);
            case CF_DIGEST("SHAKE128"):
                return Function<::CryptoPP::SHAKE128>::Compute(op);
            case CF_DIGEST("SHAKE256"):
                return Function<::CryptoPP::SHAKE256>::Compute(op);
            case CF_DIGEST("RIPEMD128"):
                return Function<::CryptoPP::RIPEMD128>::Compute(op);
            case CF_DIGEST("RIPEMD160"):
                return Function<::CryptoPP::RIPEMD160>::Compute(op);
            case CF_DIGEST("RIPEMD256"):
                return Function<::CryptoPP::RIPEMD256>::Compute(op);
            case CF_DIGEST("RIPEMD320"):
                return Function<::CryptoPP::RIPEMD320>::Compute(op);
            case CF_DIGEST("WHIRLPOOL"):
                return Function<::CryptoPP::Whirlpool>::Compute(op);
            case CF_DIGEST("MD2"):
                return Function<::CryptoPP::Weak::MD2>::Compute(op);
            case CF_DIGEST("MD4"):
                return Function<::CryptoPP::Weak::MD4>::Compute(op);
            case CF_DIGEST("MD5"):
                return Function<::CryptoPP::Weak::MD5>::Compute(op);
            case CF_DIGEST("SM3"):
                return Function<::CryptoPP::SM3>::Compute(op);
            case CF_DIGEST("BLAKE2B512"):
                return Function<::CryptoPP::BLAKE2b>::Compute(op);
            case CF_DIGEST("BLAKE2S256"):
                return Function<::CryptoPP::BLAKE2s>::Compute(op);
            case CF_DIGEST("TIGER"):
                return Function<::CryptoPP::Tiger>::Compute(op);
            case CF_DIGEST("KECCAK_224"):
                return Function<::CryptoPP::Keccak_224>::Compute(op);
            case CF_DIGEST("KECCAK_256"):
                return Function<::CryptoPP::Keccak_256>::Compute(op);
            case CF_DIGEST("KECCAK_384"):
                return Function<::CryptoPP::Keccak_384>::Compute(op);
            case CF_DIGEST("KECCAK_512"):
                return Function<::CryptoPP::Keccak_512>::Compute(op);
            case CF_DIGEST("PANAMA"):
                return Function<::CryptoPP::Weak::PanamaHash<::CryptoPP::LittleEndian>>::Compute(op);
            default:
                return std::nullopt;
        }
    }
}

namespace CryptoPP_detail {
    template <class DigestAlgorithm>
    class Digest {
        public:
            static std::optional<component::Digest> Compute(operation::Digest& op) {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                std::optional<component::Digest> ret = std::nullopt;
                DigestAlgorithm hash;
                util::Multipart parts;

                parts = util::ToParts(ds, op.cleartext);

                /* Process */
                for (const auto& part : parts) {
                    hash.Update(part.first, part.second);
                }

                /* Finalize */
                {
                    size_t digestSize = hash.DigestSize();
                    uint8_t out[digestSize];
                    hash.Final(out);

                    switch ( op.digestType.Get() ) {
                        case    CF_DIGEST("SHAKE128"):
                        case    CF_DIGEST("SHAKE256"):
                            /* For compatibility with OpenSSL */
                            digestSize /= 2;
                            break;
                    }

                    ret = component::Digest(out, digestSize);
                }

                return ret;
            }
    };
}

std::optional<component::Digest> CryptoPP::OpDigest(operation::Digest& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::Digest, component::Digest>(op);
}

namespace CryptoPP_detail {
    template <class Digest>
    class HMAC {
        public:
            static std::optional<component::MAC> Compute(operation::HMAC& op) {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                std::optional<component::MAC> ret = std::nullopt;

                ::CryptoPP::HMAC<Digest> hmac(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                util::Multipart parts = util::ToParts(ds, op.cleartext);

                /* Process */
                for (const auto& part : parts) {
                    hmac.Update(part.first, part.second);
                }

                /* Finalize */
                {
                    uint8_t out[::CryptoPP::HMAC<Digest>::DIGESTSIZE];
                    hmac.Final(out);

                    ret = component::MAC(out, ::CryptoPP::HMAC<Digest>::DIGESTSIZE);
                }

                return ret;
            }
    };
}

std::optional<component::MAC> CryptoPP::OpHMAC(operation::HMAC& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::HMAC, component::MAC>(op);
}

namespace CryptoPP_detail {

    template <class ModeCipher, size_t BlockSize, bool UseIV, bool Truncate, size_t Feedback = 0>
    std::optional<component::Ciphertext> Encrypt(operation::SymmetricEncrypt& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::Ciphertext> ret = std::nullopt;
        std::unique_ptr<typename ModeCipher::Encryption> enc = nullptr;
        std::unique_ptr<::CryptoPP::StreamTransformationFilter> encryptor = nullptr;
        util::Multipart parts;

        /* Initialize */
        {
            typename ModeCipher::Encryption enctmp;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), BlockSize);
            if ( UseIV == false ) {
                enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } else {
                if ( Feedback != 0 ) {
                    enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), Feedback);
                } else {
                    enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr());
                }
            }

            encryptor = std::make_unique<::CryptoPP::StreamTransformationFilter>(*enc, nullptr);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            encryptor->Put(part.first, part.second);
        }

        /* Finalize */
        {
            encryptor->MessageEnd();

            const size_t outSize = encryptor->MaxRetrievable();

            if ( op.ciphertextSize >= outSize ) {
                std::vector<uint8_t> out(outSize);
                encryptor->Get(out.data(), out.size());
                if ( Truncate == true ) {
                    ret = component::Ciphertext(Buffer(out.data(), op.cleartext.GetSize()));
                } else {
                    ret = component::Ciphertext(Buffer(out.data(), out.size()));
                }
            }
        }

end:
        return ret;
    }

    template <class ModeCipher, size_t BlockSize, bool UseIV, bool Truncate, size_t Feedback = 0>
    std::optional<component::Cleartext> Decrypt(operation::SymmetricDecrypt& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::Cleartext> ret = std::nullopt;
        std::unique_ptr<typename ModeCipher::Decryption> dec = nullptr;
        std::unique_ptr<::CryptoPP::StreamTransformationFilter> decryptor = nullptr;
        util::Multipart parts;

        /* Initialize */
        {
            typename ModeCipher::Decryption enctmp;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), BlockSize);
            if ( UseIV == false ) {
                dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } else {
                if ( Feedback != 0 ) {
                    dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), Feedback);
                } else {
                    dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr());
                }
            }

            decryptor = std::make_unique<::CryptoPP::StreamTransformationFilter>(*dec, nullptr);
            parts = util::ToParts(ds, op.ciphertext);
        }

        /* Process */
        for (const auto& part : parts) {
            decryptor->Put(part.first, part.second);
        }

        /* Finalize */
        {
            decryptor->MessageEnd();

            const size_t outSize = decryptor->MaxRetrievable();

            if ( op.cleartextSize >= outSize ) {
                std::vector<uint8_t> out(outSize);
                decryptor->Get(out.data(), out.size());
                if ( Truncate == true ) {
                    if ( out.size() >= op.ciphertext.GetSize() ) {
                        ret = component::Cleartext(Buffer(out.data(), op.ciphertext.GetSize()));
                    }
                } else {
                    ret = component::Cleartext(Buffer(out.data(), out.size()));
                }
            }
        }

end:
        return ret;
    }

    template <typename Cipher, size_t Feedback = 0>
    std::optional<component::Ciphertext> CryptCFB(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::CFB_Mode<Cipher>, Cipher::BLOCKSIZE, true, true, Feedback>(op);
    }

    template <typename Cipher>
    std::optional<component::Ciphertext> CryptECB(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, true>(op);
    }

    template <typename Cipher>
    std::optional<component::Ciphertext> CryptCBC(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::CBC_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Ciphertext> CryptCTR(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::CTR_Mode<Cipher>, Cipher::BLOCKSIZE, false, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Ciphertext> CryptOFB(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::OFB_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Ciphertext> CryptRaw(operation::SymmetricEncrypt& op) {
        if ( op.cleartext.GetSize() == 0 ) {
            return std::nullopt;
        }

        if ( op.cleartext.GetSize() % Cipher::BLOCKSIZE != 0 ) {
            return std::nullopt;
        }
        return Encrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, false>(op);
    }

    template <typename Cipher, size_t Feedback = 0>
    std::optional<component::Cleartext> CryptCFB(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::CFB_Mode<Cipher>, Cipher::BLOCKSIZE, true, true, Feedback>(op);
    }

    template <typename Cipher>
    std::optional<component::Cleartext> CryptECB(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, true>(op);
    }

    template <typename Cipher>
    std::optional<component::Cleartext> CryptCBC(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::CBC_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Cleartext> CryptCTR(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::CTR_Mode<Cipher>, Cipher::BLOCKSIZE, false, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Cleartext> CryptOFB(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::OFB_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
    }

    template <typename Cipher>
    std::optional<component::Cleartext> CryptRaw(operation::SymmetricDecrypt& op) {
        if ( op.ciphertext.GetSize() == 0 ) {
            return std::nullopt;
        }

        if ( op.ciphertext.GetSize() % Cipher::BLOCKSIZE != 0 ) {
            return std::nullopt;
        }
        return Decrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, false>(op);
    }

    template <class Operation, class ReturnType>
    void Crypt(Operation& op, std::optional<ReturnType>& ret) {
        ret = std::nullopt;

        try {
            switch ( op.cipher.cipherType.Get() ) {
                /* CFB */
                case    CF_CIPHER("DES_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::DES >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE3_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::DES_EDE3 >(op);
                    }
                    break;
                case    CF_CIPHER("IDEA_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::IDEA >(op);
                    }
                    break;
                case    CF_CIPHER("SEED_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SEED >(op);
                    }
                    break;
                case    CF_CIPHER("SM4_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("RC2_CFB"):
                    {
                        /* Difference
                         * ret = CryptoPP_detail::CryptCFB< ::CryptoPP::RC2 >(op);
                         */
                    }
                    break;
                case    CF_CIPHER("BF_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Blowfish >(op);
                    }
                    break;
                case    CF_CIPHER("CAST5_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::CAST128 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;

                    /* CFB8 */
                case    CF_CIPHER("DES_CFB8"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::DES, 1 >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE3_CFB8"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::DES_EDE3, 1 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::AES, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Camellia, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::ARIA, 1 >(op);
                        }
                    }
                    break;

                    /* CBC */
                case    CF_CIPHER("DESX_CBC"):
                    {
                        /* Difference
                         * ret = CryptoPP_detail::CryptCBC< ::CryptoPP::DES_XEX3 >(op);
                         */
                    }
                    break;
                case    CF_CIPHER("DES_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::DES >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::DES_EDE2 >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE3_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::DES_EDE3 >(op);
                    }
                    break;
                case    CF_CIPHER("IDEA_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::IDEA >(op);
                    }
                    break;
                case    CF_CIPHER("SEED_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SEED >(op);
                    }
                    break;
                case    CF_CIPHER("SM4_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("RC2_CBC"):
                    {
                        /* Difference
                         * ret = CryptoPP_detail::CryptCBC< ::CryptoPP::RC2 >(op);
                         */
                    }
                    break;
                case    CF_CIPHER("BF_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Blowfish >(op);
                    }
                    break;
                case    CF_CIPHER("CAST5_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::CAST128 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;

                    /* ECB */
                case    CF_CIPHER("DES_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::DES >(op);
                    }
                    break;
                case    CF_CIPHER("IDEA_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::IDEA >(op);
                    }
                    break;
                case    CF_CIPHER("SEED_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::SEED >(op);
                    }
                    break;
                case    CF_CIPHER("SM4_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("RC2_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::RC2 >(op);
                    }
                    break;
                case    CF_CIPHER("BF_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::Blowfish >(op);
                    }
                    break;
                case    CF_CIPHER("CAST5_ECB"):
                    {
                        CryptoPP_detail::CryptECB< ::CryptoPP::CAST128 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;

                    /* CTR */
                case    CF_CIPHER("SM4_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;

                    /* OFB */
                case    CF_CIPHER("DES_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::DES >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::DES_EDE2 >(op);
                    }
                    break;
                case    CF_CIPHER("DES_EDE3_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::DES_EDE3 >(op);
                    }
                    break;
                case    CF_CIPHER("IDEA_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::IDEA >(op);
                    }
                    break;
                case    CF_CIPHER("SEED_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SEED >(op);
                    }
                    break;
                case    CF_CIPHER("SM4_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("RC2_OFB"):
                    {
                        /* Difference
                         * ret = CryptoPP_detail::CryptOFB< ::CryptoPP::RC2 >(op);
                         */
                    }
                    break;
                case    CF_CIPHER("BF_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Blowfish >(op);
                    }
                    break;
                case    CF_CIPHER("CAST5_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::CAST128 >(op);
                    }
                    break;
                case    CF_CIPHER("AES_128_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;

                /* Disabled because raw AES has been observed to output 15 bytes for
                 * a 16 byte input. Needs further inspection.. */
#if 0
                /* Raw */
                case    CF_CIPHER("AES"):
                    {
                        ret = CryptoPP_detail::CryptRaw< ::CryptoPP::AES >(op);
                    }
                    break;
                case    CF_CIPHER("SERPENT"):
                    {
                        ret = CryptoPP_detail::CryptRaw< ::CryptoPP::Serpent >(op);
                    }
                    break;
                case    CF_CIPHER("TWOFISH"):
                    {
                        ret = CryptoPP_detail::CryptRaw< ::CryptoPP::Twofish >(op);
                    }
                    break;
                case    CF_CIPHER("GOST-28147-89"):
                    {
                        ret = CryptoPP_detail::CryptRaw< ::CryptoPP::GOST >(op);
                    }
                    break;
#endif
            }
        } catch ( ... ) { }
    }
}

std::optional<component::Ciphertext> CryptoPP::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    /* AEAD currently not supported */
    if ( op.tagSize != std::nullopt ) {
        return ret;
    } else if ( op.aad != std::nullopt ) {
        return ret;
    }

    CryptoPP_detail::Crypt(op, ret);

    return ret;
}

std::optional<component::Cleartext> CryptoPP::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    /* AEAD currently not supported */
    if ( op.tag != std::nullopt ) {
        return ret;
    } else if ( op.aad != std::nullopt ) {
        return ret;
    }

    CryptoPP_detail::Crypt(op, ret);

    return ret;
}

namespace CryptoPP_detail {
    template <class Digest>
    class KDF_HKDF {
        public:
        static std::optional<component::Key> Compute(operation::KDF_HKDF& op) {
            std::optional<component::Key> ret = std::nullopt;

            const size_t outSize = op.keySize;
            uint8_t* out = util::malloc(outSize);

            try {
                ::CryptoPP::HKDF<Digest> hkdf;

                hkdf.DeriveKey(
                        out,
                        outSize,
                        op.password.GetPtr(),
                        op.password.GetSize(),
                        op.salt.GetPtr(),
                        op.salt.GetSize(),
                        op.info.GetPtr(),
                        op.info.GetSize());
            } catch ( ... ) {
                goto end;
            }

            ret = component::Key(out, outSize);

end:
            util::free(out);

            return ret;
        }
    };
}

std::optional<component::Key> CryptoPP::OpKDF_HKDF(operation::KDF_HKDF& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::KDF_HKDF, component::Key>(op);
}

std::optional<component::Key> CryptoPP::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    /* Crash occurs with r == 1 */
    CF_CHECK_GTE(op.r, 1);

    try {
        ::CryptoPP::Scrypt scrypt;

        scrypt.DeriveKey(
                out,
                outSize,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.N,
                op.r,
                op.p);

    } catch ( ... ) {
        goto end;
    }

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
}

namespace CryptoPP_detail {
    template <class Digest>
    class KDF_PBKDF2 {
        public:
        static std::optional<component::Key> Compute(operation::KDF_PBKDF2& op) {
            std::optional<component::Key> ret = std::nullopt;

            const size_t outSize = op.keySize;
            uint8_t* out = util::malloc(outSize);

            try {
                ::CryptoPP::PKCS5_PBKDF2_HMAC<Digest> pbkdf2;
                pbkdf2.DeriveKey(
                        out,
                        outSize,
                        0,
                        op.password.GetPtr(),
                        op.password.GetSize(),
                        op.salt.GetPtr(),
                        op.salt.GetSize(),
                        op.iterations);
            } catch ( ... ) {
                goto end;
            }

            ret = component::Key(out, outSize);

end:
            util::free(out);

            return ret;
        }
    };
}

std::optional<component::Key> CryptoPP::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::KDF_PBKDF2, component::Key>(op);
}

} /* namespace module */
} /* namespace cryptofuzz */
