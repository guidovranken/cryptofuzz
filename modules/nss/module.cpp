#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

NSS::NSS(void) :
    Module("NSS") {
    const SECStatus rv = NSS_NoDB_Init(NULL);
    if(rv != SECSuccess) {
        printf("Cannot initialize NSS\n");
        abort();
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

std::optional<CK_MECHANISM_TYPE> NSS::toHMACCKM(const component::DigestType& digestType) const {
    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_DIGEST("SHA1"), CKM_SHA_1_HMAC },
        { CF_DIGEST("SHA224"), CKM_SHA224_HMAC },
        { CF_DIGEST("SHA256"), CKM_SHA256_HMAC },
        { CF_DIGEST("SHA384"), CKM_SHA384_HMAC },
        { CF_DIGEST("SHA512"), CKM_SHA512_HMAC },
        { CF_DIGEST("MD2"), CKM_MD2_HMAC },
        { CF_DIGEST("MD5"), CKM_MD5_HMAC },
        { CF_DIGEST("RIPEMD128"), CKM_RIPEMD128_HMAC },
        { CF_DIGEST("RIPEMD160"), CKM_RIPEMD160_HMAC },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(digestType.Get());
}

std::optional<component::MAC> NSS::OpHMAC(operation::HMAC& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;
    unsigned char out[256];

    PK11Context* ctx = nullptr;
    PK11SymKey* key = nullptr;
    PK11SlotInfo* slot = nullptr;

    std::vector<uint8_t> keyvec(op.cipher.key.GetPtr(), op.cipher.key.GetPtr() + op.cipher.key.GetSize());

    /* Initialize */
    {
        CF_CHECK_NE(slot = PK11_GetInternalSlot(), nullptr);

        std::optional<CK_MECHANISM_TYPE> ckm;
        CF_CHECK_NE(ckm = toHMACCKM(op.digestType), std::nullopt);

        {
            SECItem keyItem;
            keyItem.data = keyvec.data();
            keyItem.len = keyvec.size();
            CF_CHECK_NE(key = PK11_ImportSymKey(slot, *ckm, PK11_OriginDerive,
                    CKA_SIGN, &keyItem, nullptr), nullptr);
        }

        {
            SECItem noParams;
            noParams.data = 0;
            noParams.len = 0;
            CF_CHECK_NE(ctx = PK11_CreateContextBySymKey(*ckm, CKA_SIGN, key, &noParams), nullptr);
        }

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
        ret = component::MAC(out, outlen);
    }

end:
     if ( ctx != nullptr ) {
         PK11_DestroyContext(ctx, PR_TRUE);
     }
     if ( key != nullptr ) {
         PK11_FreeSymKey(key);
     }
     if ( slot != nullptr ) {
         PK11_FreeSlot(slot);
     }

     return ret;
}


} /* namespace module */
} /* namespace cryptofuzz */
