#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include <relic_conf.h>
#include <bls.hpp>

namespace cryptofuzz {
namespace module {

chia_bls::chia_bls(void) :
    Module("chia_bls") {
}

namespace chia_bls_detail {
    component::G1 G1_To_Component(const g1_t g1) {
        char g1str1[1024];
        char g1str2[1024];

        fp_write_str(g1str1, 1024, g1->x, 10);
        fp_write_str(g1str2, 1024, g1->y, 10);

        return {g1str1, g1str2};
    }

    component::G1 G1_To_Component(const bls::G1Element& g1El) {
        g1_t g1;
        g1El.ToNative(g1);

        return G1_To_Component(g1);
    }

    component::G2 G2_To_Component(const g2_t g2) {
        char g2str1[1024];
        char g2str2[1024];
        char g2str3[1024];
        char g2str4[1024];

        fp_write_str(g2str1, 1024, g2->x[0], 10);
        fp_write_str(g2str2, 1024, g2->y[0], 10);
        fp_write_str(g2str3, 1024, g2->x[1], 10);
        fp_write_str(g2str4, 1024, g2->y[1], 10);

        return {g2str1, g2str2, g2str3, g2str4};
    }

    component::G2 G2_To_Component(const bls::G2Element& g2El) {
        g2_t g2;
        g2El.ToNative(g2);

        return G2_To_Component(g2);
    }

    template <class T>
    //std::vector<uint8_t> MsgAug(const component::Cleartext& cleartext, const component::Cleartext& aug) {
    std::vector<uint8_t> MsgAug(const T& op) {
        std::vector<uint8_t> msg;
        const auto aug = op.aug.Get();
        const auto ct = op.cleartext.Get();
        msg.insert(msg.end(), aug.begin(), aug.end());
        msg.insert(msg.end(), ct.begin(), ct.end());
        return msg;
    }
}

std::optional<component::BLS_KeyPair> chia_bls::OpBLS_GenerateKeyPair(operation::BLS_GenerateKeyPair& op) {
    std::optional<component::BLS_KeyPair> ret = std::nullopt;

    if ( op.ikm.GetSize() < 32 ) {
        return ret;
    }
    if ( op.info.GetSize() != 0 ) {
        return ret;
    }

    const auto priv = bls::HDKeys::KeyGen(op.ikm.Get());
    const auto pub = priv.GetG1Element();
    uint8_t priv_bytes[bls::PrivateKey::PRIVATE_KEY_SIZE];
    priv.Serialize(priv_bytes);
    ret = {
        util::BinToDec(priv_bytes, sizeof(priv_bytes)),
        chia_bls_detail::G1_To_Component(pub)};

    ret = std::nullopt;

    return ret;
}

std::optional<component::BLS_PublicKey> chia_bls::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::BLS_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        std::optional<std::vector<uint8_t>> priv_bytes;
        CF_CHECK_NE(priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32), std::nullopt);
        bls::PrivateKey priv = bls::PrivateKey::FromBytes(bls::Bytes(*priv_bytes));
        auto pub = priv.GetG1Element();

        ret = chia_bls_detail::G1_To_Component(pub);
    } catch ( std::invalid_argument ) { }

end:
    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.dest.GetSize() > 255 ) {
        return std::nullopt;
    }

    g1_st* g1 = bls::Util::SecAlloc<g1_st>(1);

    const auto msg = chia_bls_detail::MsgAug(op);
    ep_map_dst(g1, msg.data(), msg.size(), op.dest.GetPtr(), op.dest.GetSize());

    ret = chia_bls_detail::G1_To_Component(g1);

    bls::Util::SecFree(g1);

    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.dest.GetSize() > 255 ) {
        return std::nullopt;
    }

    g2_t g2;
    g2_new(g2);

    const auto msg = chia_bls_detail::MsgAug(op);
    ep2_map_dst(g2, msg.data(), msg.size(), op.dest.GetPtr(), op.dest.GetSize());

    ret = chia_bls_detail::G2_To_Component(g2);

    g2_free(g2);

    return ret;
}

std::optional<bool> chia_bls::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;
    return ret;

    g1_t g1;
    g1_new(g1);
    g1_null(g1);

    CF_CHECK_LT(op.g1.first.ToTrimmedString().size(), 100);
    CF_CHECK_LT(op.g1.second.ToTrimmedString().size(), 100);

    RLC_TRY {
        fp_read_str(g1->x, op.g1.first.ToTrimmedString().c_str(), op.g1.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g1->y, op.g1.second.ToTrimmedString().c_str(), op.g1.second.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    ret = ep_on_curve(g1) != 0;

    //ret = g1_is_valid(g1) != 0;

    ///* XXX discrepancy */ ret = std::nullopt;

    /* More extensive check: */
#if 0
    {
        try {
            /* FromNative calls CheckValid */
            const auto G1 = bls::G1Element::FromNative(&g1);
            (void)G1;
            ret = true;
        } catch ( std::invalid_argument ) {
            ret = false;
        }
    }
#endif

end:
    return ret;
}

std::optional<component::BLS_Signature> chia_bls::OpBLS_Sign(operation::BLS_Sign& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }
    if ( op.hashOrPoint == false ) {
        return std::nullopt;
    }
    if ( op.dest.GetSize() > 255 ) {
        return std::nullopt;
    }

    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        std::optional<std::vector<uint8_t>> priv_bytes;
        CF_CHECK_NE(priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32), std::nullopt);
        bls::PrivateKey priv = bls::PrivateKey::FromBytes(bls::Bytes(*priv_bytes));
        auto pub = priv.GetG1Element();
        const auto msg = chia_bls_detail::MsgAug(op);
        //bls::G2Element sig = bls::BasicSchemeMPL().Sign(priv, op.cleartext.Get());
        //bls::G2Element sig = priv.SignG2(op.cleartext.GetPtr(), op.cleartext.GetSize(), op.dest.GetPtr(), op.dest.GetSize());
        bls::G2Element sig = priv.SignG2(msg.data(), msg.size(), op.dest.GetPtr(), op.dest.GetSize());
        {
            g2_t g2;
            sig.ToNative(g2);
            char sigstr1[1024];
            char sigstr2[1024];
            char sigstr3[1024];
            char sigstr4[1024];

            fp_write_str(sigstr1, 1024, g2->x[0], 10);
            fp_write_str(sigstr2, 1024, g2->y[0], 10);
            fp_write_str(sigstr3, 1024, g2->x[1], 10);
            fp_write_str(sigstr4, 1024, g2->y[1], 10);

            //ret = {sigstr1, sigstr2, sigstr3, sigstr4};
            ret = {{sigstr1, sigstr2, sigstr3, sigstr4}, chia_bls_detail::G1_To_Component(pub)};
        }
    } catch ( std::invalid_argument ) {
        if ( !op.priv.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184512") ) {
            CF_ASSERT(0, "Failed to sign");
        }
    }

end:
    return ret;
}

std::optional<bool> chia_bls::OpBLS_Verify(operation::BLS_Verify& op) {
    (void)op;
    return std::nullopt;
#if 0
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    if ( op.pub.first.ToTrimmedString() == "0" ) return std::nullopt;
    if ( op.pub.second.ToTrimmedString() == "0" ) return std::nullopt;
    if ( op.signature.first.first.ToTrimmedString() == "0" ) return std::nullopt;
    if ( op.signature.first.second.ToTrimmedString() == "0" ) return std::nullopt;
    if ( op.signature.second.first.ToTrimmedString() == "0" ) return std::nullopt;
    if ( op.signature.second.second.ToTrimmedString() == "0" ) return std::nullopt;

    std::optional<bool> ret = std::nullopt;

    g1_t g1;
    g1_null(g1);
    g1_new(g1);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);

    RLC_TRY {
        fp_read_str(g1->x, op.pub.first.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g1->y, op.pub.first.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->x[0], op.signature.first.first.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->y[0], op.signature.first.second.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->x[1], op.signature.second.first.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->y[1], op.signature.second.second.ToTrimmedString().c_str(), op.pub.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    {
        try {
            const auto pub = bls::G1Element::FromNative(&g1);
            const auto sig = bls::G2Element::FromNative(&g2);

            //ret = bls::BasicSchemeMPL().Verify(pub, op.cleartext.Get(), sig);
            bls::G2Element hashedPoint = bls::G2Element::FromMessage(op.cleartext.Get(), op.dest.GetPtr(), op.dest.GetSize());

            g1_t *g1s = new g1_t[2];
            g2_t *g2s = new g2_t[2];

            bls::G1Element::Generator().Negate().ToNative(g1s);
            pub.ToNative(g1s + 1);
            sig.ToNative(g2s);
            hashedPoint.ToNative(g2s + 1);

            //bool ans = bls::CoreMPL::NativeVerify(g1s, g2s, 2);
            {
                gt_t target, candidate, tmpPairing;
                fp12_zero(target);
                fp_set_dig(target[0][0][0], 1);
                fp12_zero(candidate);
                fp_set_dig(candidate[0][0][0], 1);

                // prod e(pubkey[i], hash[i]) * e(-g1, aggSig)
                // Performs pubKeys.size() pairings, 250 at a time

                for (size_t i = 0; i < 2; i += 250) {
                    size_t numPairings = std::min((2 - i), (size_t)250);
                    pc_map_sim(tmpPairing, g1s + i, g2s + i, numPairings);
                    fp12_mul(candidate, candidate, tmpPairing);
                }

                // 1 =? prod e(pubkey[i], hash[i]) * e(-g1, aggSig)
                if (gt_cmp(target, candidate) != RLC_EQ || core_get()->code != RLC_OK) {
                    core_get()->code = RLC_OK;
                    ret = false;
                }

                if ( ret == std::nullopt ) {
                    bls::BLS::CheckRelicErrors();
                    ret = true;
                }
            }

            delete[] g1s;
            delete[] g2s;
        } catch ( ... ) { }
    }
end:
    g1_free(g1);
    g2_free(g2);

    return ret;
#endif
}

std::optional<component::Key> chia_bls::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }

    if ( op.keySize == 0 ) {
        return ret;
    }

    if ( op.keySize > (255*32) ) {
        return ret;
    }

    uint8_t* out = util::malloc(op.keySize);

    CF_NORET( bls::HKDF256::ExtractExpand(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.info.GetPtr(), op.info.GetSize()) );

    ret = component::Key(out, op.keySize);

    util::free(out);

    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::vector<uint8_t>> compressed = std::nullopt;

    CF_CHECK_NE(compressed = util::DecToBin(op.compressed.ToTrimmedString(), 48), std::nullopt);

    try {
        const auto g1 = bls::G1Element::FromBytes(::bls::Bytes(*compressed));
        ret = chia_bls_detail::G1_To_Component(g1);
    } catch ( std::invalid_argument ) {
        //ret = component::G1{"0", "0"};
    }

end:
    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::vector<uint8_t>> compressed_x = std::nullopt;
    std::optional<std::vector<uint8_t>> compressed_y = std::nullopt;
    std::vector<uint8_t> compressed;


    CF_CHECK_NE(compressed_x = util::DecToBin(op.compressed.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(compressed_y = util::DecToBin(op.compressed.second.ToTrimmedString(), 48), std::nullopt);
    compressed = util::Append(*compressed_x, *compressed_y);

    try {
        const auto g2 = bls::G2Element::FromBytes(::bls::Bytes(compressed));
        ret = chia_bls_detail::G2_To_Component(g2);
    } catch ( std::invalid_argument ) {
        //ret = component::G2{"0", "0"};
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
