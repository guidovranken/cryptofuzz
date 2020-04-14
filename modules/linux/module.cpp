#include "module.h"
#include <cryptofuzz/util.h>
#include <kcapi.h>

namespace cryptofuzz {
namespace module {

Linux::Linux(void) :
    Module("Linux") {
    kcapi_set_verbosity(KCAPI_LOG_NONE);
}

namespace Linux_detail {

std::optional<std::string> toDigestString(const component::DigestType& digestType) {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, std::string> LUT = {
        /* CRC32 mismatches with libgcrypt. TODO. */
        //{ CF_DIGEST("CRC32"), "crc32" },
        { CF_DIGEST("MD5"), "md5" },
        { CF_DIGEST("SHA1"), "sha1" },
        { CF_DIGEST("SHA224"), "sha224" },
        { CF_DIGEST("SHA256"), "sha256" },
        { CF_DIGEST("SHA384"), "sha384" },
        { CF_DIGEST("SHA512"), "sha512" },
        { CF_DIGEST("SKEIN_1024"), "skein1024" },
        /* SKEIN_256 mismatches with Monero. Unclear which one is wrong. TODO. */
        //{ CF_DIGEST("SKEIN_256"), "skein256" },
        { CF_DIGEST("SKEIN_512"), "skein512" },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(digestType.Get());
}

const std::string parenthesize(const std::string parent, const std::string child) {
    static const std::string pOpen("(");
    static const std::string pClose(")");

    return parent + pOpen + child + pClose;
}

template <class Operation, class ReturnType>
std::optional<ReturnType> digest_hmac(Operation& op, const bool hmac = false) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t* out = nullptr;
    size_t outSize;
    util::Multipart parts;
    struct kcapi_handle *handle = NULL;

    /* Initialize */
    {
        const auto _digestString = Linux_detail::toDigestString(op.digestType);
        CF_CHECK_NE(_digestString, std::nullopt);

        std::string digestString = *_digestString;
        if ( hmac == true ) {
            digestString = parenthesize("hmac", *_digestString);
        }

        CF_CHECK_EQ(kcapi_md_init(&handle, digestString.c_str(), 0), 0);
        outSize = kcapi_md_digestsize(handle);
        out = (uint8_t*)malloc(outSize);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_GTE(kcapi_md_update(handle, part.first, part.second), 0);
    }

    /* Finalize */
    {
        CF_CHECK_GTE(kcapi_md_final(handle, out, outSize), 0);
        ret = ReturnType(out, outSize);
    }

end:
    free(out);
	kcapi_md_destroy(handle);
    return ret;
}

} /* namespace Linux_detail */

std::optional<component::Digest> Linux::OpDigest(operation::Digest& op) {
    return Linux_detail::digest_hmac<operation::Digest, component::Digest>(op);
}

std::optional<component::MAC> Linux::OpHMAC(operation::HMAC& op) {
    return Linux_detail::digest_hmac<operation::HMAC, component::MAC>(op, true);
}

std::optional<component::Key> Linux::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);
    std::string hmacString;

    /* Initialize */
    {
        const auto digestString = Linux_detail::toDigestString(op.digestType);
        CF_CHECK_NE(digestString, std::nullopt);

        hmacString = Linux_detail::parenthesize("hmac", *digestString);
    }

    /* Process */
    {
        CF_CHECK_EQ(kcapi_hkdf(
                    hmacString.c_str(),
                    op.password.GetPtr(),
                    op.password.GetSize(),
                    op.salt.GetPtr(),
                    op.salt.GetSize(),
                    op.info.GetPtr(),
                    op.info.GetSize(),
                    out,
                    op.keySize), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    util::free(out);
    return ret;
}

std::optional<component::Key> Linux::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);
    std::string hmacString;

    /* Initialize */
    {
        /* TODO report: if iterations == 0, output buffer is left uninitialized/zeroed */
        CF_CHECK_GT(op.iterations, 0);

        const auto digestString = Linux_detail::toDigestString(op.digestType);
        CF_CHECK_NE(digestString, std::nullopt);

        hmacString = Linux_detail::parenthesize("hmac", *digestString);
    }

    /* Process */
    {
        CF_CHECK_EQ(kcapi_pbkdf(
                    hmacString.c_str(),
                    op.password.GetPtr(),
                    op.password.GetSize(),
                    op.salt.GetPtr(),
                    op.salt.GetSize(),
                    op.iterations,
                    out,
                    op.keySize), 0);
    }

    /* Finalize */
    {
        /* Disabled because wrong result observed */
        ret = component::Key(out, op.keySize);
    }

end:
    util::free(out);

    return ret;

}

} /* namespace module */
} /* namespace cryptofuzz */
