#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <adler32.h>
#include <aes.h>
#include <aria.h>
#include <blake2.h>
#include <blowfish.h>
#include <camellia.h>
#include <cast.h>
#include <cham.h>
#include <crc.h>
#include <cryptlib.h>
#include <des.h>
#include <eccrypto.h>
#include <ecp.h>
#include <filters.h>
#include <gost.h>
#include <hkdf.h>
#include <hmac.h>
#include <idea.h>
#include <kalyna.h>
#include <keccak.h>
#include <lea.h>
#include <hight.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <modes.h>
#include <oids.h>
#include <osrng.h>
#include <panama.h>
#include <pwdbased.h>
#include <rc2.h>
#include <rc6.h>
#include <ripemd.h>
#include <scrypt.h>
#include <safer.h>
#include <seed.h>
#include <serpent.h>
#include <sha.h>
#include <shake.h>
#include <shark.h>
#include <simeck.h>
#include <simon.h>
#include <siphash.h>
#include <skipjack.h>
#include <sm3.h>
#include <sm4.h>
#include <speck.h>
#include <square.h>
#include <tiger.h>
#include <twofish.h>
#include <whrlpool.h>
#include <xts.h>
#include <memory>

#include "bn_ops.h"

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

    template <bool Is128Bit>
    std::optional<component::MAC> SipHash(operation::HMAC& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::MAC> ret = std::nullopt;

        try {
            ::CryptoPP::SipHash<2, 4, Is128Bit> siphash(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            util::Multipart parts = util::ToParts(ds, op.cleartext);

            /* Process */
            for (const auto& part : parts) {
                siphash.Update(part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[::CryptoPP::SipHash<2, 4, Is128Bit>::DIGESTSIZE];
                siphash.Final(out);

                ret = component::MAC(out, ::CryptoPP::SipHash<2, 4, Is128Bit>::DIGESTSIZE);
            }
        } catch ( ... ) { }

        return ret;
    }
}

std::optional<component::MAC> CryptoPP::OpHMAC(operation::HMAC& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SIPHASH64"):
            {
                return CryptoPP_detail::SipHash<false>(op);
            }
        case CF_DIGEST("SIPHASH128"):
            {
                return CryptoPP_detail::SipHash<true>(op);
            }
        default:
            return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::HMAC, component::MAC>(op);
    }
}

namespace CryptoPP_detail {

    template <
        class ModeCipher,
        size_t BlockSize,
        bool UseIV,
        bool Truncate,
        size_t Feedback = 0,
        ::CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme Padding = ::CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
    >
    std::optional<component::Ciphertext> Encrypt(operation::SymmetricEncrypt& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::Ciphertext> ret = std::nullopt;
        std::unique_ptr<typename ModeCipher::Encryption> enc = nullptr;
        std::unique_ptr<::CryptoPP::StreamTransformationFilter> encryptor = nullptr;
        util::Multipart parts;

        /* Initialize */
        {
            typename ModeCipher::Encryption enctmp;
            if ( UseIV == false ) {
                enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } else {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), BlockSize);
                if ( Feedback != 0 ) {
                    enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), Feedback);
                } else {
                    enc = std::make_unique<typename ModeCipher::Encryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr());
                }
            }

            encryptor = std::make_unique<::CryptoPP::StreamTransformationFilter>(*enc, nullptr, Padding);
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

    template <
        class ModeCipher,
        size_t BlockSize,
        bool UseIV,
        bool Truncate,
        size_t Feedback = 0,
        ::CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme Padding = ::CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
    >
    std::optional<component::Cleartext> Decrypt(operation::SymmetricDecrypt& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::Cleartext> ret = std::nullopt;
        std::unique_ptr<typename ModeCipher::Decryption> dec = nullptr;
        std::unique_ptr<::CryptoPP::StreamTransformationFilter> decryptor = nullptr;
        util::Multipart parts;

        /* Initialize */
        {
            typename ModeCipher::Decryption enctmp;
            if ( UseIV == false ) {
                dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize());
            } else {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), BlockSize);
                if ( Feedback != 0 ) {
                    dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(), Feedback);
                } else {
                    dec = std::make_unique<typename ModeCipher::Decryption>(op.cipher.key.GetPtr(), op.cipher.key.GetSize(), op.cipher.iv.GetPtr());
                }
            }

            decryptor = std::make_unique<::CryptoPP::StreamTransformationFilter>(*dec, nullptr, Padding);
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
        return Encrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, false, 0, ::CryptoPP::BlockPaddingSchemeDef::NO_PADDING>(op);
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
    std::optional<component::Ciphertext> CryptXTS(operation::SymmetricEncrypt& op) {
        return Encrypt<::CryptoPP::XTS_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
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
        return Decrypt<::CryptoPP::ECB_Mode<Cipher>, Cipher::BLOCKSIZE, false, false, 0, ::CryptoPP::BlockPaddingSchemeDef::NO_PADDING>(op);
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
    std::optional<component::Cleartext> CryptXTS(operation::SymmetricDecrypt& op) {
        return Decrypt<::CryptoPP::XTS_Mode<Cipher>, Cipher::BLOCKSIZE, true, false>(op);
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
                case    CF_CIPHER("KALYNA128_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna128 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna256 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_CFB"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna512 >(op);
                        }
                    }
                    break;
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
                case    CF_CIPHER("SIMON64_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SIMON64>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON128_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SIMON128>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK64_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SPECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK128_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SPECK128>(op);
                    }
                    break;
                case    CF_CIPHER("SQUARE_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Square>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM64_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::CHAM64>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM128_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::CHAM128>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK32_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SIMECK32>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK64_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SIMECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_K_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SAFER_K>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_SK_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SAFER_SK>(op);
                    }
                    break;

                    /* CFB8 */
                case    CF_CIPHER("KALYNA128_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna128, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna256, 1 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_CFB8"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptCFB< ::CryptoPP::Kalyna512, 1 >(op);
                        }
                    }
                    break;
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
                case    CF_CIPHER("HIGHT_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::HIGHT>(op);
                    }
                    break;
                case    CF_CIPHER("LEA_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::LEA>(op);
                    }
                    break;
                case    CF_CIPHER("SKIPJACK_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SKIPJACK>(op);
                    }
                    break;
                case    CF_CIPHER("RC6_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::RC6>(op);
                    }
                    break;
                case    CF_CIPHER("SHARK_CFB"):
                    {
                        ret = CryptoPP_detail::CryptCFB< ::CryptoPP::SHARK>(op);
                    }
                    break;

                    /* CBC */
                case    CF_CIPHER("KALYNA128_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Kalyna128 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Kalyna256 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_CBC"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Kalyna512 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("DESX_B_CBC"):
                    {
                         ret = CryptoPP_detail::CryptCBC< ::CryptoPP::DES_XEX3 >(op);
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
                case    CF_CIPHER("HIGHT_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::HIGHT>(op);
                    }
                    break;
                case    CF_CIPHER("LEA_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::LEA>(op);
                    }
                    break;
                case    CF_CIPHER("SKIPJACK_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SKIPJACK>(op);
                    }
                    break;
                case    CF_CIPHER("RC6_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::RC6>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON64_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SIMON64>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON128_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SIMON128>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK64_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SPECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK128_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SPECK128>(op);
                    }
                    break;
                case    CF_CIPHER("SQUARE_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::Square>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM64_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::CHAM64>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM128_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::CHAM128>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK32_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SIMECK32>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK64_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SIMECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SHARK_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SHARK>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_K_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SAFER_K>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_SK_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::SAFER_SK>(op);
                    }
                    break;
                case    CF_CIPHER("GOST-28147-89_CBC"):
                    {
                        ret = CryptoPP_detail::CryptCBC< ::CryptoPP::GOST >(op);
                    }
                    break;

                    /* ECB */
                case    CF_CIPHER("KALYNA128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Kalyna128 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Kalyna256 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            CryptoPP_detail::CryptECB< ::CryptoPP::Kalyna512 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("DES_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::DES >(op);
                    }
                    break;
                case    CF_CIPHER("IDEA_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::IDEA >(op);
                    }
                    break;
                case    CF_CIPHER("SEED_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SEED >(op);
                    }
                    break;
                case    CF_CIPHER("SM4_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SM4 >(op);
                    }
                    break;
                case    CF_CIPHER("RC2_ECB"):
                    {
                        /* Difference
                         * ret = CryptoPP_detail::CryptECB< ::CryptoPP::RC2 >(op);
                         */
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
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("CAMELLIA_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::Camellia >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_128_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_192_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 192 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("ARIA_256_ECB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptECB< ::CryptoPP::ARIA >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("HIGHT_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::HIGHT>(op);
                    }
                    break;
                case    CF_CIPHER("LEA_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::LEA>(op);
                    }
                    break;
                case    CF_CIPHER("SKIPJACK_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SKIPJACK>(op);
                    }
                    break;
                case    CF_CIPHER("RC6_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::RC6>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON64_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SIMON64>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON128_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SIMON128>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK64_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SPECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK128_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SPECK128>(op);
                    }
                    break;
                case    CF_CIPHER("SQUARE_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::Square>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM64_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::CHAM64>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM128_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::CHAM128>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK32_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SIMECK32>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK64_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SIMECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SHARK_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SHARK>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_K_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SAFER_K>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_SK_ECB"):
                    {
                        ret = CryptoPP_detail::CryptECB< ::CryptoPP::SAFER_SK>(op);
                    }
                    break;

                    /* CTR */
                case    CF_CIPHER("KALYNA128_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Kalyna128 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Kalyna256 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_CTR"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Kalyna512 >(op);
                        }
                    }
                    break;
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
                case    CF_CIPHER("HIGHT_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::HIGHT>(op);
                    }
                    break;
                case    CF_CIPHER("LEA_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::LEA>(op);
                    }
                    break;
                case    CF_CIPHER("SKIPJACK_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SKIPJACK>(op);
                    }
                    break;
                case    CF_CIPHER("RC6_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::RC6>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON64_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SIMON64>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON128_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SIMON128>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK64_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SPECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK128_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SPECK128>(op);
                    }
                    break;
                case    CF_CIPHER("SQUARE_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::Square>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM64_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::CHAM64>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM128_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::CHAM128>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK32_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SIMECK32>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK64_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SIMECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SHARK_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SHARK>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_K_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SAFER_K>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_SK_CTR"):
                    {
                        ret = CryptoPP_detail::CryptCTR< ::CryptoPP::SAFER_SK>(op);
                    }
                    break;

                    /* OFB */
                case    CF_CIPHER("KALYNA128_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Kalyna128 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA256_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Kalyna256 >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("KALYNA512_OFB"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Kalyna512 >(op);
                        }
                    }
                    break;
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
                case    CF_CIPHER("HIGHT_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::HIGHT>(op);
                    }
                    break;
                case    CF_CIPHER("LEA_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::LEA>(op);
                    }
                    break;
                case    CF_CIPHER("SKIPJACK_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SKIPJACK>(op);
                    }
                    break;
                case    CF_CIPHER("RC6_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::RC6>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON64_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SIMON64>(op);
                    }
                    break;
                case    CF_CIPHER("SIMON128_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SIMON128>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK64_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SPECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SPECK128_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SPECK128>(op);
                    }
                    break;
                case    CF_CIPHER("SQUARE_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::Square>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM64_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::CHAM64>(op);
                    }
                    break;
                case    CF_CIPHER("CHAM128_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::CHAM128>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK32_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SIMECK32>(op);
                    }
                    break;
                case    CF_CIPHER("SIMECK64_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SIMECK64>(op);
                    }
                    break;
                case    CF_CIPHER("SHARK_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SHARK>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_K_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SAFER_K>(op);
                    }
                    break;
                case    CF_CIPHER("SAFER_SK_OFB"):
                    {
                        ret = CryptoPP_detail::CryptOFB< ::CryptoPP::SAFER_SK>(op);
                    }
                    break;

                /* XTS */
                case    CF_CIPHER("AES_128_XTS"):
                    {
                        if ( op.cipher.key.GetSize() == 128 / 8) {
                            ret = CryptoPP_detail::CryptXTS< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_256_XTS"):
                    {
                        if ( op.cipher.key.GetSize() == 256 / 8) {
                            ret = CryptoPP_detail::CryptXTS< ::CryptoPP::AES >(op);
                        }
                    }
                    break;
                case    CF_CIPHER("AES_512_XTS"):
                    {
                        if ( op.cipher.key.GetSize() == 512 / 8) {
                            ret = CryptoPP_detail::CryptXTS< ::CryptoPP::AES >(op);
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

    template <class Digest>
    class KDF_PBKDF {
        public:
            static std::optional<component::Key> Compute(operation::KDF_PBKDF& op) {
                std::optional<component::Key> ret = std::nullopt;

                uint8_t* out = util::malloc(op.keySize);

                try {
                    ::CryptoPP::PKCS12_PBKDF<Digest> pbkdf1;
                    pbkdf1.DeriveKey(
                            out,
                            op.keySize,
                            1,
                            op.password.GetPtr(),
                            op.password.GetSize(),
                            op.salt.GetPtr(),
                            op.salt.GetSize(),
                            op.iterations,
                            0.0f);
                } catch ( ... ) {
                    goto end;
                }

                ret = component::Key(out, op.keySize);

end:
                util::free(out);

                return ret;
            }
    };

    template <class Digest>
    class KDF_PBKDF1 {
        public:
        static std::optional<component::Key> Compute(operation::KDF_PBKDF1& op) {
            std::optional<component::Key> ret = std::nullopt;


            const size_t outSize = op.keySize;
            uint8_t* out = util::malloc(outSize);

            /* TODO The following two checks are to work around the bugs described
             * in https://github.com/weidai11/cryptopp/issues/874
             * Remove these checks once fixed in upstream
             */
            CF_CHECK_NE(op.keySize, 0);
            CF_CHECK_LTE(op.keySize, Digest::DIGESTSIZE);

            try {
                ::CryptoPP::PKCS5_PBKDF1<Digest> pbkdf1;
                pbkdf1.DeriveKey(
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

std::optional<component::Key> CryptoPP::OpKDF_PBKDF(operation::KDF_PBKDF& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::KDF_PBKDF, component::Key>(op);
}

std::optional<component::Key> CryptoPP::OpKDF_PBKDF1(operation::KDF_PBKDF1& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::KDF_PBKDF1, component::Key>(op);
}

std::optional<component::Key> CryptoPP::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    return CryptoPP_detail::InvokeByDigest<CryptoPP_detail::KDF_PBKDF2, component::Key>(op);
}

namespace CryptoPP_detail {
    const ::CryptoPP::DL_GroupParameters_EC<::CryptoPP::ECP>& ResolveCurve(const component::CurveType& curveType) {
        static const std::map<uint64_t, const ::CryptoPP::DL_GroupParameters_EC<::CryptoPP::ECP>> LUT = {
            { CF_ECC_CURVE("brainpool160r1"), ::CryptoPP::ASN1::brainpoolP160r1() },
            { CF_ECC_CURVE("brainpool192r1"), ::CryptoPP::ASN1::brainpoolP192r1() },
            { CF_ECC_CURVE("brainpool224r1"), ::CryptoPP::ASN1::brainpoolP224r1() },
            { CF_ECC_CURVE("brainpool256r1"), ::CryptoPP::ASN1::brainpoolP256r1() },
            { CF_ECC_CURVE("brainpool320r1"), ::CryptoPP::ASN1::brainpoolP320r1() },
            { CF_ECC_CURVE("brainpool384r1"), ::CryptoPP::ASN1::brainpoolP384r1() },
            { CF_ECC_CURVE("brainpool512r1"), ::CryptoPP::ASN1::brainpoolP512r1() },
            { CF_ECC_CURVE("secp112r1"), ::CryptoPP::ASN1::secp112r1() },
            { CF_ECC_CURVE("secp112r2"), ::CryptoPP::ASN1::secp112r2() },
            { CF_ECC_CURVE("secp128r1"), ::CryptoPP::ASN1::secp128r1() },
            { CF_ECC_CURVE("secp128r2"), ::CryptoPP::ASN1::secp128r2() },
            { CF_ECC_CURVE("secp160k1"), ::CryptoPP::ASN1::secp160k1() },
            { CF_ECC_CURVE("secp160r1"), ::CryptoPP::ASN1::secp160r1() },
            { CF_ECC_CURVE("secp160r2"), ::CryptoPP::ASN1::secp160r2() },
            { CF_ECC_CURVE("secp192k1"), ::CryptoPP::ASN1::secp192k1() },
            { CF_ECC_CURVE("secp224k1"), ::CryptoPP::ASN1::secp224k1() },
            { CF_ECC_CURVE("secp224r1"), ::CryptoPP::ASN1::secp224r1() },
            { CF_ECC_CURVE("secp256k1"), ::CryptoPP::ASN1::secp256k1() },
            { CF_ECC_CURVE("secp384r1"), ::CryptoPP::ASN1::secp384r1() },
            { CF_ECC_CURVE("secp521r1"), ::CryptoPP::ASN1::secp521r1() },
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            throw std::exception();
        }

        return LUT.at(curveType.Get());
    }
}

std::optional<component::ECC_PublicKey> CryptoPP::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ::CryptoPP::ECDSA<::CryptoPP::ECP, ::CryptoPP::SHA256>::PrivateKey privateKey;
    ::CryptoPP::ECDSA<::CryptoPP::ECP, ::CryptoPP::SHA256>::PublicKey publicKey;

    const ::CryptoPP::Integer privStr(op.priv.ToString(ds).c_str());

    try {
        const ::CryptoPP::DL_GroupParameters_EC<::CryptoPP::ECP>& curve = CryptoPP_detail::ResolveCurve(op.curveType);
        privateKey.Initialize(curve, privStr);
    } catch ( ... ) {
        goto end;
    }

    privateKey.MakePublicKey(publicKey);

    ret = {
        ::CryptoPP::IntToString<>(publicKey.GetPublicElement().x, 10),
        ::CryptoPP::IntToString<>(publicKey.GetPublicElement().y, 10),
    };

end:
    return ret;
}

std::optional<bool> CryptoPP::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const ::CryptoPP::Integer pubXStr(op.pub.first.ToString(ds).c_str());
    const ::CryptoPP::Integer pubYStr(op.pub.first.ToString(ds).c_str());
    const ::CryptoPP::Integer sigRStr(op.signature.first.ToString(ds).c_str());
    const ::CryptoPP::Integer sigSStr(op.signature.second.ToString(ds).c_str());

    ::CryptoPP::ECP::Point pubPoint(pubXStr, pubYStr);
    ::CryptoPP::ECDSA<::CryptoPP::ECP, ::CryptoPP::SHA256>::PublicKey publicKey;

    /* TODO digest type */

    try {
        const ::CryptoPP::DL_GroupParameters_EC<::CryptoPP::ECP>& curve = CryptoPP_detail::ResolveCurve(op.curveType);
        publicKey.Initialize(curve, pubPoint);
    } catch ( ... ) {
        goto end;
    }

    {
        ::CryptoPP::ECDSA<::CryptoPP::ECP, ::CryptoPP::SHA256>::Verifier verifier(publicKey);

        const size_t expectedSignatureLength = verifier.SignatureLength();
        if ( (expectedSignatureLength % 2) != 0 ) abort();
        uint8_t signature[expectedSignatureLength];

        sigRStr.Encode(signature + 0, expectedSignatureLength / 2);
        sigSStr.Encode(signature + (expectedSignatureLength / 2), expectedSignatureLength / 2);

        try {
            ret = verifier.VerifyMessage(op.cleartext.GetPtr(), op.cleartext.GetSize(), signature, sizeof(signature));
        } catch ( ... ) { }
    }

end:
    return ret;
}

std::optional<component::Bignum> CryptoPP::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ::CryptoPP::Integer res("0");
    std::vector<::CryptoPP::Integer> bn{
        ::CryptoPP::Integer(op.bn0.ToString(ds).c_str()),
        ::CryptoPP::Integer(op.bn1.ToString(ds).c_str()),
        ::CryptoPP::Integer(op.bn2.ToString(ds).c_str()),
        ::CryptoPP::Integer(op.bn3.ToString(ds).c_str())
    };
    std::unique_ptr<CryptoPP_bignum::Operation> opRunner = nullptr;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Div>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<CryptoPP_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::Sqr>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::GCD>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::SqrMod>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::InvMod>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<CryptoPP_bignum::MulMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Cmp>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::LCM>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::Abs>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::Neg>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::IsZero>();
            break;
        case    CF_CALCOP("And(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::And>();
            break;
        case    CF_CALCOP("Or(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Or>();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Xor>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<CryptoPP_bignum::IsOdd>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::Bit>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<CryptoPP_bignum::ClearBit>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);

    try {
        CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);
    } catch ( ... ) {
        goto end;
    }

    ret = { IntToString(res, 10) };

end:

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
