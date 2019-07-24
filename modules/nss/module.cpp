#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

NSS::NSS(void) :
    Module("NSS") {
    /* Copied from curl */
    if(!NSS_IsInitialized() && !nss_context) {
        static NSSInitParameters params;
        params.length = sizeof(params);
        nss_context = NSS_InitContext("", "", "", "", &params, NSS_INIT_READONLY
                | NSS_INIT_NOCERTDB   | NSS_INIT_NOMODDB       | NSS_INIT_FORCEOPEN
                | NSS_INIT_NOROOTINIT | NSS_INIT_OPTIMIZESPACE | NSS_INIT_PK11RELOAD);
    }
}

std::optional<SECOidTag> NSS::toOID(const component::DigestType& digestType) const {
    static const std::map<uint64_t, SECOidTag> LUT = {
        { CF_DIGEST("SHA1"), SEC_OID_SHA1 },
        { CF_DIGEST("SHA224"), SEC_OID_SHA224 },
        { CF_DIGEST("SHA256"), SEC_OID_SHA256 },
        { CF_DIGEST("SHA384"), SEC_OID_SHA384 },
        { CF_DIGEST("SHA512"), SEC_OID_SHA512 },
        { CF_DIGEST("MD2"), SEC_OID_MD2 },
        { CF_DIGEST("MD4"), SEC_OID_MD4 },
        { CF_DIGEST("MD5"), SEC_OID_MD5 },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(digestType.Get());
}

std::optional<component::Digest> NSS::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;
    unsigned char out[256];

    /* TODO scoped ? */
    PK11Context* ctx = nullptr;

    /* Initialize */
    {
        std::optional<SECOidTag> oid;
        CF_CHECK_NE(oid = toOID(op.digestType), std::nullopt);
        CF_CHECK_NE(ctx = PK11_CreateDigestContext(*oid), nullptr);
        CF_CHECK_EQ(PK11_DigestBegin(ctx), SECSuccess);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(PK11_DigestOp(ctx, part.first, part.second), SECSuccess);
    }

    /* Finalize */
    {
        unsigned int outlen;
        CF_CHECK_EQ(PK11_DigestFinal(ctx, out, &outlen, sizeof(out)), SECSuccess);
        ret = component::Digest(out, outlen);
    }

end:
     if ( ctx != nullptr ) {
         PK11_DestroyContext(ctx, PR_TRUE);
     }

     return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
