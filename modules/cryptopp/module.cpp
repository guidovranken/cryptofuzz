#include "module.h"
#include <cryptofuzz/util.h>
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
#include <hmac.h>
#include <memory>

namespace cryptofuzz {
namespace module {

CryptoPP::CryptoPP(void) :
    Module("Crypto++") { }


std::optional<component::Digest> CryptoPP::OpDigest(operation::Digest& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;
    std::unique_ptr<::CryptoPP::HashTransformation> hash = nullptr;
    util::Multipart parts;

    try {
        switch ( op.digestType.Get() ) {
            case CF_DIGEST("SHA1"):
                hash = std::make_unique<::CryptoPP::SHA1>();
                break;
            case CF_DIGEST("SHA224"):
                hash = std::make_unique<::CryptoPP::SHA224>();
                break;
            case CF_DIGEST("SHA384"):
                hash = std::make_unique<::CryptoPP::SHA384>();
                break;
            case CF_DIGEST("SHA512"):
                hash = std::make_unique<::CryptoPP::SHA512>();
                break;
            case CF_DIGEST("SHAKE128"):
                hash = std::make_unique<::CryptoPP::SHAKE128>();
                break;
            case CF_DIGEST("SHAKE256"):
                hash = std::make_unique<::CryptoPP::SHAKE256>();
                break;
            case CF_DIGEST("RIPEMD128"):
                hash = std::make_unique<::CryptoPP::RIPEMD128>();
                break;
            case CF_DIGEST("RIPEMD160"):
                hash = std::make_unique<::CryptoPP::RIPEMD160>();
                break;
            case CF_DIGEST("RIPEMD256"):
                hash = std::make_unique<::CryptoPP::RIPEMD256>();
                break;
            case CF_DIGEST("RIPEMD320"):
                hash = std::make_unique<::CryptoPP::RIPEMD320>();
                break;
            case CF_DIGEST("WHIRLPOOL"):
                hash = std::make_unique<::CryptoPP::Whirlpool>();
                break;
            case CF_DIGEST("MD2"):
                hash = std::make_unique<::CryptoPP::Weak::MD2>();
                break;
            case CF_DIGEST("MD4"):
                hash = std::make_unique<::CryptoPP::Weak::MD4>();
                break;
            case CF_DIGEST("MD5"):
                hash = std::make_unique<::CryptoPP::Weak::MD5>();
                break;
            case CF_DIGEST("SM3"):
                hash = std::make_unique<::CryptoPP::SM3>();
                break;
            case CF_DIGEST("BLAKE2B512"):
                hash = std::make_unique<::CryptoPP::BLAKE2b>();
                break;
            case CF_DIGEST("BLAKE2S256"):
                hash = std::make_unique<::CryptoPP::BLAKE2s>();
                break;
            case CF_DIGEST("TIGER"):
                hash = std::make_unique<::CryptoPP::Tiger>();
                break;
        }

        CF_CHECK_NE(hash, nullptr);

        parts = util::ToParts(ds, op.cleartext);

        /* Process */
        for (const auto& part : parts) {
            hash->Update(part.first, part.second);
        }

        /* Finalize */
        {
            size_t digestSize = hash->DigestSize();
            uint8_t out[digestSize];
            hash->Final(out);

            switch ( op.digestType.Get() ) {
                case    CF_DIGEST("SHAKE128"):
                case    CF_DIGEST("SHAKE256"):
                    /* For compatibility with OpenSSL */
                    digestSize /= 2;
                break;
            }

            ret = component::Digest(out, digestSize);
        }
    } catch ( ::CryptoPP::Exception ) { }

end:
    return ret;
}

namespace CryptoPP_detail {
    template <class Digest>
    std::optional<component::MAC> HMAC(operation::HMAC& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::MAC> ret = std::nullopt;

        try {
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
        } catch ( ::CryptoPP::Exception ) { }

        return ret;
    }
}

std::optional<component::MAC> CryptoPP::OpHMAC(operation::HMAC& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHA1>(op);
        case CF_DIGEST("SHA224"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHA224>(op);
        case CF_DIGEST("SHA384"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHA384>(op);
        case CF_DIGEST("SHA512"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHA512>(op);
        case CF_DIGEST("SHAKE128"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHAKE128>(op);
        case CF_DIGEST("SHAKE256"):
            return CryptoPP_detail::HMAC<::CryptoPP::SHAKE256>(op);
        case CF_DIGEST("RIPEMD128"):
            return CryptoPP_detail::HMAC<::CryptoPP::RIPEMD128>(op);
        case CF_DIGEST("RIPEMD160"):
            return CryptoPP_detail::HMAC<::CryptoPP::RIPEMD160>(op);
        case CF_DIGEST("RIPEMD256"):
            return CryptoPP_detail::HMAC<::CryptoPP::RIPEMD256>(op);
        case CF_DIGEST("RIPEMD320"):
            return CryptoPP_detail::HMAC<::CryptoPP::RIPEMD320>(op);
        case CF_DIGEST("WHIRLPOOL"):
            return CryptoPP_detail::HMAC<::CryptoPP::Whirlpool>(op);
        case CF_DIGEST("MD2"):
            return CryptoPP_detail::HMAC<::CryptoPP::Weak::MD2>(op);
        case CF_DIGEST("MD4"):
            return CryptoPP_detail::HMAC<::CryptoPP::Weak::MD4>(op);
        case CF_DIGEST("MD5"):
            return CryptoPP_detail::HMAC<::CryptoPP::Weak::MD5>(op);
        case CF_DIGEST("SM3"):
            return CryptoPP_detail::HMAC<::CryptoPP::SM3>(op);
        case CF_DIGEST("BLAKE2B512"):
            return CryptoPP_detail::HMAC<::CryptoPP::BLAKE2b>(op);
        case CF_DIGEST("BLAKE2S256"):
            return CryptoPP_detail::HMAC<::CryptoPP::BLAKE2s>(op);
        case CF_DIGEST("TIGER"):
            return CryptoPP_detail::HMAC<::CryptoPP::Tiger>(op);
    }

    return std::nullopt;
}

} /* namespace module */
} /* namespace cryptofuzz */
