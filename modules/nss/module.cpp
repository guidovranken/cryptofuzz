#include "module.h"
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <nss.h>
#include <pk11pub.h>
#include <nss_scoped_ptrs.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

NSS::NSS(void) :
    Module("NSS") {
    setenv("NSS_STRICT_NOFORK", "DISABLED", 1);
    const SECStatus rv = NSS_NoDB_Init(NULL);
    if(rv != SECSuccess) {
        printf("Cannot initialize NSS\n");
        abort();
    }

    NSS_bignum::Initialize();
}

NSS::~NSS(void) {
    NSS_Shutdown();
}

namespace nss_detail {
    std::optional<SECOidTag> toOID(const component::DigestType& digestType) {
        static const std::map<uint64_t, SECOidTag> LUT = {
            { CF_DIGEST("SHA1"), SEC_OID_SHA1 },
            { CF_DIGEST("SHA224"), SEC_OID_SHA224 },
            { CF_DIGEST("SHA256"), SEC_OID_SHA256 },
            { CF_DIGEST("SHA384"), SEC_OID_SHA384 },
            { CF_DIGEST("SHA512"), SEC_OID_SHA512 },
            /* awaiting fix https://bugzilla.mozilla.org/show_bug.cgi?id=1575923 { CF_DIGEST("MD2"), SEC_OID_MD2 }, */
            { CF_DIGEST("MD4"), SEC_OID_MD4 },
            { CF_DIGEST("MD5"), SEC_OID_MD5 },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }
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
        CF_CHECK_NE(oid = nss_detail::toOID(op.digestType), std::nullopt);
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

namespace nss_detail {
    std::optional<CK_MECHANISM_TYPE> toHMACCKM(const component::DigestType& digestType) {
        static const std::map<uint64_t, uint64_t> LUT = {
            { CF_DIGEST("SHA1"), CKM_SHA_1_HMAC },
            { CF_DIGEST("SHA224"), CKM_SHA224_HMAC },
            { CF_DIGEST("SHA256"), CKM_SHA256_HMAC },
            { CF_DIGEST("SHA384"), CKM_SHA384_HMAC },
            { CF_DIGEST("SHA512"), CKM_SHA512_HMAC },
            /* awaiting fix https://bugzilla.mozilla.org/show_bug.cgi?id=1575923 { CF_DIGEST("MD2"), CKM_MD2_HMAC }, */
            { CF_DIGEST("MD5"), CKM_MD5_HMAC },
            { CF_DIGEST("RIPEMD128"), CKM_RIPEMD128_HMAC },
            { CF_DIGEST("RIPEMD160"), CKM_RIPEMD160_HMAC },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }
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
        CF_CHECK_NE(ckm = nss_detail::toHMACCKM(op.digestType), std::nullopt);

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

std::optional<component::MAC> NSS::OpCMAC(operation::CMAC& op) {
    if ( op.cipher.cipherType.Get() != CF_CIPHER("AES") ) {
        return std::nullopt;
    }

    std::optional<component::MAC> ret = std::nullopt;

    std::vector<uint8_t> output(AES_BLOCK_SIZE);
    std::vector<uint8_t> keyvec(op.cipher.key.GetPtr(), op.cipher.key.GetPtr() + op.cipher.key.GetSize());
    std::vector<uint8_t> ctvec(op.cleartext.GetPtr(), op.cleartext.GetPtr() + op.cleartext.GetSize());

    SECItem key_item = {siBuffer, keyvec.data(), static_cast<uint32_t>(keyvec.size())};
    SECItem output_item = {siBuffer, output.data(), AES_BLOCK_SIZE};
    SECItem data_item = {siBuffer, ctvec.data(), static_cast<uint32_t>(ctvec.size())};

    PK11SlotInfo* slot = nullptr;
    PK11SymKey* p11_key = nullptr;
    CF_CHECK_NE(slot = PK11_GetInternalSlot(), nullptr);

    CF_CHECK_NE(p11_key = PK11_ImportSymKey(slot, CKM_AES_CMAC, PK11_OriginUnwrap, CKA_SIGN, &key_item, nullptr), nullptr);
    CF_CHECK_EQ(PK11_SignWithSymKey(p11_key, CKM_AES_CMAC, nullptr, &output_item, &data_item), SECSuccess);

    ret = component::MAC(output.data(), output.size());

end:
    if ( p11_key != nullptr ) {
        PK11_FreeSymKey(p11_key);
    }
    if ( slot != nullptr ) {
        PK11_FreeSlot(slot);
    }

    return ret;
}

namespace nss_detail {
    std::optional<CK_MECHANISM_TYPE> toCipherCKM(const component::SymmetricCipherType& cipherType) {
        static const std::map<uint64_t, uint64_t> LUT = {
            //{ CF_CIPHER("RC2_CBC"), CKM_RC2_CBC },
            //{ CF_CIPHER("RC4"), CKM_RC4 },
            { CF_CIPHER("DES_CBC"), CKM_DES_CBC },
            { CF_CIPHER("DES_ECB"), CKM_DES_ECB },
            { CF_CIPHER("AES_128_CBC"), CKM_AES_CBC },
            { CF_CIPHER("AES_128_ECB"), CKM_AES_ECB },
            { CF_CIPHER("AES_128_CTR"), CKM_AES_CTR },
            { CF_CIPHER("AES_128_CCM"), CKM_AES_CCM },
            { CF_CIPHER("IDEA_CBC"), CKM_IDEA_CBC },
            { CF_CIPHER("IDEA_ECB"), CKM_IDEA_ECB },
            { CF_CIPHER("BF_CBC"), CKM_BLOWFISH_CBC },
            { CF_CIPHER("SEED_CBC"), CKM_SEED_CBC },
            { CF_CIPHER("CAST5_CBC"), CKM_CAST5_CBC },
            { CF_CIPHER("CAST5_ECB"), CKM_CAST5_ECB },
            { CF_CIPHER("CAMELLIA_128_CBC"), CKM_CAMELLIA_CBC },
            { CF_CIPHER("CAMELLIA_128_ECB"), CKM_CAMELLIA_ECB },
            { CF_CIPHER("SEED_ECB"), CKM_SEED_ECB },
            { CF_CIPHER("AES_128_GCM"), CKM_AES_GCM },
            { CF_CIPHER("AES_192_GCM"), CKM_AES_GCM },
            { CF_CIPHER("AES_256_GCM"), CKM_AES_GCM },
            { CF_CIPHER("CHACHA20_POLY1305"), CKM_NSS_CHACHA20_POLY1305},
#if 1
            { 30, CKM_CAST3_CBC },
            { 31, CKM_CAST3_ECB },
            { 32, CKM_CDMF_CBC},
            { 0, CKM_BATON_CBC128},
            { 1, CKM_BATON_COUNTER},
            { 2, CKM_BATON_ECB128},
            { 3, CKM_BATON_ECB96},
            { 4, CKM_BATON_KEY_GEN},
            { 5, CKM_BATON_SHUFFLE},
            { 6, CKM_BATON_WRAP},
            { 7, CKM_SKIPJACK_CBC64},
            { 8, CKM_SKIPJACK_CFB16},
            { 9, CKM_SKIPJACK_CFB32},
            {10, CKM_SKIPJACK_CFB64},
            {11, CKM_SKIPJACK_CFB8},
            {12, CKM_SKIPJACK_ECB64},
            {13, CKM_SKIPJACK_KEY_GEN},
            {14, CKM_SKIPJACK_OFB64},
            {15, CKM_SKIPJACK_PRIVATE_WRAP},
            {16, CKM_SKIPJACK_RELAYX},
            {17, CKM_SKIPJACK_WRAP},
#endif
        };

        if ( LUT.find(cipherType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(cipherType.Get());
    }
}

namespace nss_detail {
    template <class OperationType>
    util::Multipart ToParts(Datasource& ds, const OperationType& op);

    template <>
    util::Multipart ToParts<>(Datasource& ds, const operation::SymmetricEncrypt& op) {
        return util::ToParts(ds, op.cleartext);
    }

    template <>
    util::Multipart ToParts<>(Datasource& ds, const operation::SymmetricDecrypt& op) {
        return util::ToParts(ds, op.ciphertext);
    }

    template <class OperationType>
    CK_ATTRIBUTE_TYPE GetAttributeType(void);

    template <>
    CK_ATTRIBUTE_TYPE GetAttributeType<operation::SymmetricEncrypt>(void) {
        return CKA_ENCRYPT;
    }

    template <>
    CK_ATTRIBUTE_TYPE GetAttributeType<operation::SymmetricDecrypt>(void) {
        return CKA_DECRYPT;
    }

    template <class OperationType>
    size_t GetInSize(const OperationType& op);

    template <> size_t GetInSize<>(const operation::SymmetricEncrypt& op) {
        return op.cleartext.GetSize();
    }

    template <class OperationType>
    const uint8_t* GetInPtr(const OperationType& op);

    template <> const uint8_t* GetInPtr<>(const operation::SymmetricEncrypt& op) {
        return op.cleartext.GetPtr();
    }

    template <class OperationType>
    size_t GetOutSize(const OperationType& op);

    template <> size_t GetOutSize<>(const operation::SymmetricEncrypt& op) {
        return op.ciphertextSize;
    }

    template <> size_t GetInSize<>(const operation::SymmetricDecrypt& op) {
        return op.ciphertext.GetSize();
    }

    template <> const uint8_t* GetInPtr<>(const operation::SymmetricDecrypt& op) {
        return op.ciphertext.GetPtr();
    }

    template <> size_t GetOutSize<>(const operation::SymmetricDecrypt& op) {
        return op.cleartextSize;
    }

    template <class OperationType>
    size_t GetTagSize(const OperationType& op);

    template <>
    size_t GetTagSize<>(const operation::SymmetricEncrypt& op) {
        return op.tagSize == std::nullopt ? 0 : *op.tagSize;
    }

    template <>
    size_t GetTagSize<>(const operation::SymmetricDecrypt& op) {
        return op.tag == std::nullopt ? 0 : op.tag->GetSize();
    }

    template <class OperationType>
    SECStatus CryptOneShot(PK11SymKey* key, CK_MECHANISM_TYPE ckm, SECItem* param, uint8_t* out, OperationType& op, unsigned int* outLen);

    template <> SECStatus CryptOneShot<>(PK11SymKey* key, CK_MECHANISM_TYPE ckm, SECItem* param, uint8_t* out, operation::SymmetricEncrypt& op, unsigned int* outLen) {
        return PK11_Encrypt(
                key,
                ckm,
                param,
                out,
                outLen,
                GetOutSize(op),
                GetInPtr(op),
                GetInSize(op));
    }

    template <> SECStatus CryptOneShot<>(PK11SymKey* key, CK_MECHANISM_TYPE ckm, SECItem* param, uint8_t* out, operation::SymmetricDecrypt& op, unsigned int* outLen) {
        uint8_t const* inPtr;
        size_t inSize;

        std::vector<uint8_t> invec;
        if ( repository::IsAEAD(op.cipher.cipherType.Get()) && op.tag != std::nullopt ) {
            std::vector<uint8_t> ciphertextvec(GetInPtr(op), GetInPtr(op) + GetInSize(op));
            std::vector<uint8_t> tagvec(op.tag->GetPtr(), op.tag->GetPtr() + op.tag->GetSize());

            std::copy(ciphertextvec.begin(), ciphertextvec.end(), std::back_inserter(invec));
            std::copy(tagvec.begin(), tagvec.end(), std::back_inserter(invec));

            inPtr = invec.data();
            inSize = invec.size();
        } else {
            inPtr = GetInPtr(op),
            inSize = GetInSize(op);
        }

        return PK11_Decrypt(
                key,
                ckm,
                param,
                out,
                outLen,
                GetOutSize(op),
                inPtr,
                inSize);
    }

    template <class ReturnType, class OperationType>
    ReturnType CreateReturnValue(
            const OperationType& op,
            const uint8_t* data,
            const size_t size);

    template <> component::Ciphertext CreateReturnValue(
            const operation::SymmetricEncrypt& op,
            const uint8_t* data,
            const size_t size) {
        if ( repository::IsAEAD(op.cipher.cipherType.Get()) ) {
            if ( size != op.cleartext.GetSize() + GetTagSize(op) ) {
                printf("%zu, %zu %zu\n", size, op.cleartext.GetSize(), GetTagSize(op));
                abort();
            }
            return component::Ciphertext(
                    Buffer(data, op.cleartext.GetSize()),
                    Buffer(data + op.cleartext.GetSize(), GetTagSize(op)));
        } else {
            return component::Ciphertext(Buffer(data, size));
        }
    }

    template <> component::Cleartext CreateReturnValue(
            const operation::SymmetricDecrypt& op,
            const uint8_t* data,
            const size_t size) {
        (void)op;
        return component::Cleartext(Buffer(data, size));
    }

    template <class ReturnType, class OperationType>
    std::optional<ReturnType> Crypt(OperationType& op) {
        std::optional<ReturnType> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        uint8_t* out = util::malloc(GetOutSize(op));

        PK11SymKey* key = nullptr;
        PK11SlotInfo* slot = nullptr;
        SECItem* param = nullptr;
        PK11Context* ctx = nullptr;
        CK_NSS_GCM_PARAMS* gcm_params = nullptr;

        size_t outIdx = 0;
        util::Multipart parts;
        bool useOneShot = true;

        std::vector<uint8_t> keyvec(op.cipher.key.GetPtr(), op.cipher.key.GetPtr() + op.cipher.key.GetSize());
        std::vector<uint8_t> ivvec(op.cipher.iv.GetPtr(), op.cipher.iv.GetPtr() + op.cipher.iv.GetSize());
        std::vector<uint8_t> aadvec;
        if ( op.aad != std::nullopt ) {
            aadvec = std::vector<uint8_t>(op.aad->GetPtr(), op.aad->GetPtr() + op.aad->GetSize());
        }

        std::optional<CK_MECHANISM_TYPE> ckm;

        /* Initialize */
        {
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);
            CF_CHECK_GT(op.cipher.iv.GetSize(), 0);
            CF_CHECK_GT(GetInSize(op), 0);

            CF_CHECK_NE(ckm = nss_detail::toCipherCKM(op.cipher.cipherType), std::nullopt);

            CF_CHECK_NE(slot = PK11_GetInternalSlot(), nullptr);

            CF_CHECK_GT(GetOutSize(op), 0);

            {
                SECItem keyItem;
                keyItem.data = keyvec.data();
                keyItem.len = keyvec.size();
                CF_CHECK_NE(key = PK11_ImportSymKey(slot, *ckm, PK11_OriginDerive,
                            CKA_SIGN, &keyItem, nullptr), nullptr);
            }

            if ( op.cipher.cipherType.Get() == CF_CIPHER("AES_128_CTR") ) {
                CK_AES_CTR_PARAMS* aes_ctr_params = nullptr;
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

                CF_CHECK_NE(param = (SECItem *)PORT_Alloc(sizeof(SECItem)), nullptr);
                CF_CHECK_NE(aes_ctr_params = (CK_AES_CTR_PARAMS*)PORT_Alloc(sizeof(CK_AES_CTR_PARAMS)), nullptr);

                aes_ctr_params->ulCounterBits = 128;
                memcpy(aes_ctr_params->cb, op.cipher.iv.GetPtr(), 16);

                param->type = siBuffer;
                param->data = (unsigned char *)aes_ctr_params;
                param->len = sizeof(*aes_ctr_params);
            } else if ( repository::IsAEAD(op.cipher.cipherType.Get()) == false ) {
                SECItem ivItem = {siBuffer, ivvec.data(), (unsigned int)ivvec.size()};
                CF_CHECK_NE(param = PK11_ParamFromIV(*ckm, &ivItem), nullptr);
            } else {
                CF_CHECK_NE(param = (SECItem *)PORT_Alloc(sizeof(SECItem)), nullptr);
                CF_CHECK_NE(gcm_params = (CK_NSS_GCM_PARAMS*)PORT_Alloc(sizeof(CK_NSS_GCM_PARAMS)), nullptr);

                gcm_params->pIv = ivvec.data();
                gcm_params->ulIvLen = ivvec.size();
                gcm_params->pAAD = aadvec.data();
                gcm_params->ulAADLen = aadvec.size();
                gcm_params->ulTagBits = GetTagSize(op) * 8;

                param->type = siBuffer;
                param->data = (unsigned char *)gcm_params;
                param->len = sizeof(*gcm_params);
            }

            if ( repository::IsAEAD(op.cipher.cipherType.Get()) == false ) {
                try {
                    useOneShot = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) {
                }
            }

            if ( useOneShot == false ) {
                CF_CHECK_NE(ctx = PK11_CreateContextBySymKey(*ckm, GetAttributeType<OperationType>(), key, param), nullptr);
                parts = ToParts(ds, op);
            }
        }

        if ( useOneShot == true ) {
            unsigned int outLen;
            const auto res = CryptOneShot<OperationType>(key, *ckm, param, out, op, &outLen);
            if ( res == SECSuccess ) {
                if ( GetOutSize(op) > 0 ) /* Workaround for crash */ {
                    ret = CreateReturnValue<ReturnType, OperationType>(op, out, outLen);
                }
            }
        } else {
            /* Process */
            {
                for (const auto& part : parts) {
                    if ( part.second == 0 ) {
                        continue;
                    }

                    int outLen;
                    CF_CHECK_EQ(PK11_CipherOp(
                                ctx,
                                out + outIdx,
                                &outLen,
                                GetOutSize(op) - outIdx,
                                part.first,
                                part.second), SECSuccess);
                    if ( outLen < 0 ) abort(); /* XXX ? */
                    outIdx += outLen;
                }
            }

            /* Finalize */
            {
                unsigned int outLen;
                CF_CHECK_EQ(PK11_DigestFinal(ctx, out + outIdx, &outLen, GetOutSize(op) - outIdx), SECSuccess);
                outIdx += outLen;
                if ( GetOutSize(op) > 0 ) /* Workaround for crash */ {
                    ret = CreateReturnValue<ReturnType, OperationType>(op, out, outIdx);
                }
            }
        }

end:
        util::free(out);

        if ( key != nullptr ) {
            PK11_FreeSymKey(key);
        }
        if ( param != nullptr ) {
            SECITEM_FreeItem(param, PR_TRUE);
        }
        if ( slot != nullptr ) {
            PK11_FreeSlot(slot);
        }
        if ( ctx != nullptr ) {
            PK11_DestroyContext(ctx, PR_TRUE);
        }
        return ret;
    }

}

std::optional<component::Ciphertext> NSS::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = nss_detail::Crypt<component::Ciphertext, operation::SymmetricEncrypt>(op);
    if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
        return std::nullopt;
    } else {
        return ret;
    }
}

std::optional<component::Cleartext> NSS::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = nss_detail::Crypt<component::Cleartext, operation::SymmetricDecrypt>(op);
    if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
        return std::nullopt;
    } else {
        return ret;
    }
}

namespace nss_detail {
    std::optional<CK_MECHANISM_TYPE> toHKDFCKM(const component::DigestType& digestType) {
        static const std::map<uint64_t, uint64_t> LUT = {
            { CF_DIGEST("SHA1"), CKM_NSS_HKDF_SHA1 },
            { CF_DIGEST("SHA256"), CKM_NSS_HKDF_SHA256 },
            { CF_DIGEST("SHA384"), CKM_NSS_HKDF_SHA384 },
            { CF_DIGEST("SHA512"), CKM_NSS_HKDF_SHA512 },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }
}

std::optional<component::Key> NSS::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    std::optional<CK_MECHANISM_TYPE> ckm;
    SECItem ikmItem = {siBuffer, const_cast<uint8_t *>(op.password.GetPtr()), static_cast<uint32_t>(op.password.GetSize())};
    SECItem* okmItem = nullptr;
    ScopedPK11SlotInfo slot;
    ScopedPK11SymKey ikm;
    ScopedPK11SymKey okm;

    /* Initialize */
    CK_NSS_HKDFParams hkdfParams = {true, const_cast<unsigned char*>(op.salt.GetPtr()), op.salt.GetSize(),
                                    true, const_cast<unsigned char*>(op.info.GetPtr()), op.info.GetSize()};
    SECItem kdfParams = {siBuffer, (unsigned char*)&hkdfParams, sizeof(hkdfParams)};

    CF_CHECK_NE(ckm = nss_detail::toHKDFCKM(op.digestType), std::nullopt);
    slot = ScopedPK11SlotInfo(PK11_GetInternalSlot());
    CF_CHECK_NE(slot.get(), nullptr);
    ikm = ScopedPK11SymKey(PK11_ImportSymKey(slot.get(), CKM_GENERIC_SECRET_KEY_GEN, PK11_OriginUnwrap, CKA_DERIVE,
                &ikmItem, nullptr));
    CF_CHECK_NE(ikm.get(), nullptr);

    /* Derive */
    okm = ScopedPK11SymKey(PK11_Derive(ikm.get(), *ckm, &kdfParams, CKM_AES_KEY_GEN, CKA_DERIVE, static_cast<int32_t>(op.keySize)));
    CF_CHECK_NE(okm.get(), nullptr);
    CF_CHECK_EQ(PK11_ExtractKeyValue(okm.get()), SECSuccess);
    CF_CHECK_NE(okmItem = PK11_GetKeyData(okm.get()), nullptr);

    ret = component::Key(okmItem->data, okmItem->len);

end:
    return ret;
}

namespace nss_detail {
    std::optional<SECOidTag> toHMACOID(const component::DigestType& digestType) {
        static const std::map<uint64_t, SECOidTag> LUT = {
            { CF_DIGEST("SHA1"), SEC_OID_HMAC_SHA1 },
            { CF_DIGEST("SHA224"), SEC_OID_HMAC_SHA224 },
            { CF_DIGEST("SHA256"), SEC_OID_HMAC_SHA256 },
            { CF_DIGEST("SHA384"), SEC_OID_HMAC_SHA384 },
            { CF_DIGEST("SHA512"), SEC_OID_HMAC_SHA512 },
            { CF_DIGEST("MD5"), SEC_OID_HMAC_MD5 },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }
}

std::optional<component::Key> NSS::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    ScopedSECAlgorithmID algId;
    std::optional<SECOidTag> oid;
    SECItem* keyData = nullptr;
    PK11SymKey* key = nullptr;
    PK11SlotInfo* slot = nullptr;

    /* Initialize */
    SECItem passItem = {siBuffer, const_cast<uint8_t *>(op.password.GetPtr()), static_cast<uint32_t>(op.password.GetSize())};
    SECItem saltItem = {siBuffer, const_cast<uint8_t *>(op.salt.GetPtr()), static_cast<uint32_t>(op.salt.GetSize())};
    CF_CHECK_GT(op.salt.GetSize(), 0);
    CF_CHECK_GT(op.keySize, 0);
    CF_CHECK_LTE(op.keySize, 256); /* Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1591363 */
    CF_CHECK_NE(oid = nss_detail::toHMACOID(op.digestType), std::nullopt);
    algId = ScopedSECAlgorithmID(PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2, /* unused */ SEC_OID_PKCS5_PBKDF2, *oid, op.keySize,
                op.iterations, &saltItem));
    CF_CHECK_NE(algId.get(), nullptr);

    /* Derive */
    CF_CHECK_NE(slot = PK11_GetInternalSlot(), nullptr);
    CF_CHECK_NE(key = PK11_PBEKeyGen(slot, algId.get(), &passItem, false, nullptr), nullptr);
    CF_CHECK_EQ(PK11_ExtractKeyValue(key), SECSuccess);
    CF_CHECK_NE(keyData = PK11_GetKeyData(key), nullptr);

    ret = component::Key(keyData->data, keyData->len);

end:
    if ( key != nullptr ) {
        PK11_FreeSymKey(key);
    }
    if ( slot != nullptr ) {
        PK11_FreeSlot(slot);
    }

    return ret;
}

std::optional<component::Bignum> NSS::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::vector<NSS_bignum::Bignum> bn(4);
    NSS_bignum::Bignum res;
    std::unique_ptr<NSS_bignum::Operation> opRunner = nullptr;

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToTrimmedString()), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Div>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<NSS_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<NSS_bignum::Sqr>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<NSS_bignum::GCD>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<NSS_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<NSS_bignum::SubMod>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<NSS_bignum::MulMod>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<NSS_bignum::SqrMod>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<NSS_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Cmp>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<NSS_bignum::LCM>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<NSS_bignum::Abs>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<NSS_bignum::Neg>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<NSS_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<NSS_bignum::IsOdd>();
            break;
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<NSS_bignum::Exp>();
            break;
        case    CF_CALCOP("Mod_NIST_256(A)"):
            opRunner = std::make_unique<NSS_bignum::Mod_NIST_256>();
            break;
        case    CF_CALCOP("Mod_NIST_384(A)"):
            opRunner = std::make_unique<NSS_bignum::Mod_NIST_384>();
            break;
        case    CF_CALCOP("Mod_NIST_521(A)"):
            opRunner = std::make_unique<NSS_bignum::Mod_NIST_521>();
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
