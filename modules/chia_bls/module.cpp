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
    CF_ASSERT(core_get(), "relic not properly initialized");
}

namespace chia_bls_detail {
    component::G1 G1_To_Component(g1_t g1) {
        char g1str1[1024];
        char g1str2[1024];

        ep_norm(g1, g1);

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
    Buffer MsgAug(const T& op) {
        std::vector<uint8_t> msg;
        const auto aug = op.aug.Get();
        const auto ct = op.cleartext.Get();
        msg.insert(msg.end(), aug.begin(), aug.end());
        msg.insert(msg.end(), ct.begin(), ct.end());
        return Buffer(msg);
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

std::optional<component::G2> chia_bls::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        std::optional<std::vector<uint8_t>> priv_bytes;
        CF_CHECK_NE(priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32), std::nullopt);
        bls::PrivateKey priv = bls::PrivateKey::FromBytes(bls::Bytes(*priv_bytes));
        auto pub = priv.GetG2Element();

        ret = chia_bls_detail::G2_To_Component(pub);
    } catch ( std::invalid_argument ) { }

end:
    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.dest.GetSize() > 255 ) {
        return std::nullopt;
    }

    g1_st* g1 = bls::Util::SecAlloc<g1_st>(1);

    const auto msg = chia_bls_detail::MsgAug(op);
    ep_map_dst(g1, msg.GetPtr(&ds), msg.GetSize(), op.dest.GetPtr(&ds), op.dest.GetSize());

    ret = chia_bls_detail::G1_To_Component(g1);

    bls::Util::SecFree(g1);

    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.dest.GetSize() > 255 ) {
        return std::nullopt;
    }

    g2_t g2;
    g2_new(g2);

    const auto msg = chia_bls_detail::MsgAug(op);
    ep2_map_dst(g2, msg.GetPtr(&ds), msg.GetSize(), op.dest.GetPtr(&ds), op.dest.GetSize());

    ret = chia_bls_detail::G2_To_Component(g2);

    g2_free(g2);

    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_MapToG1(operation::BLS_MapToG1& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::vector<uint8_t> pseudo_random_bytes;

    {
        const auto u = util::DecToBin(op.u.ToTrimmedString(), 64);
        if ( u == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), u->begin(), u->end());
    }

    {
        const auto v = util::DecToBin(op.v.ToTrimmedString(), 64);
        if ( v == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), v->begin(), v->end());
    }

    g1_st* g1 = bls::Util::SecAlloc<g1_st>(1);

    ep_map_from_field(g1, pseudo_random_bytes.data(), 128);

    ret = chia_bls_detail::G1_To_Component(g1);

    bls::Util::SecFree(g1);

    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_MapToG2(operation::BLS_MapToG2& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::vector<uint8_t> pseudo_random_bytes;

    {
        const auto u_x = util::DecToBin(op.u.first.ToTrimmedString(), 64);
        if ( u_x == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), u_x->begin(), u_x->end());
    }
    {
        const auto u_y = util::DecToBin(op.u.second.ToTrimmedString(), 64);
        if ( u_y == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), u_y->begin(), u_y->end());
    }
    {
        const auto v_x = util::DecToBin(op.v.first.ToTrimmedString(), 64);
        if ( v_x == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), v_x->begin(), v_x->end());
    }
    {
        const auto v_y = util::DecToBin(op.v.second.ToTrimmedString(), 64);
        if ( v_y == std::nullopt ) {
            return std::nullopt;
        }
        pseudo_random_bytes.insert(pseudo_random_bytes.end(), v_y->begin(), v_y->end());
    }

    g2_st* g2 = bls::Util::SecAlloc<g2_st>(1);

    ep2_map_from_field(g2, pseudo_random_bytes.data(), 256);

    ret = chia_bls_detail::G2_To_Component(g2);

    bls::Util::SecFree(g2);

    return ret;
}

std::optional<bool> chia_bls::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    g1_t g1;
    g1_new(g1);
    g1_null(g1);

    CF_CHECK_NE(op.g1.first.ToTrimmedString(), "0");
    CF_CHECK_NE(op.g1.second.ToTrimmedString(), "0");

    CF_CHECK_LT(op.g1.first.ToTrimmedString().size(), 120);
    CF_CHECK_LT(op.g1.second.ToTrimmedString().size(), 120);

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

    fp_read_str(g1->z, "1", 1, 10);

    {
        try {
            const auto G1 = bls::G1Element::FromNative(g1);
            G1.CheckValid();
            (void)G1;
            ret = true;
        } catch ( std::invalid_argument ) {
            ret = false;
        }
    }

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
        bls::G2Element sig = priv.SignG2(msg.GetPtr(&ds), msg.GetSize(), op.dest.GetPtr(&ds), op.dest.GetSize());
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
    static const std::vector<uint8_t> dst{
      0x42, 0x4c, 0x53, 0x5f, 0x53, 0x49, 0x47, 0x5f, 0x42, 0x4c, 0x53, 0x31,
      0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53,
      0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f,
      0x52, 0x4f, 0x5f, 0x4e, 0x55, 0x4c, 0x5f};

    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }
    if ( op.hashOrPoint == false ) {
        return std::nullopt;
    }

    std::optional<bool> ret = std::nullopt;

    g1_t g1;
    g1_null(g1);
    g1_new(g1);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);

    const auto pub_x = op.pub.first.ToTrimmedString();
    const auto pub_y = op.pub.second.ToTrimmedString();
    const auto sig_v = op.signature.first.first.ToTrimmedString();
    const auto sig_w = op.signature.first.second.ToTrimmedString();
    const auto sig_x = op.signature.second.first.ToTrimmedString();
    const auto sig_y = op.signature.second.second.ToTrimmedString();

    CF_CHECK_EQ(op.dest.Get(), dst);

    CF_CHECK_NE(pub_x, "0");
    CF_CHECK_NE(pub_y, "0");
    CF_CHECK_NE(sig_v, "0");
    CF_CHECK_NE(sig_w, "0");
    CF_CHECK_NE(sig_x, "0");
    CF_CHECK_NE(sig_y, "0");

    CF_CHECK_LT(pub_x.size(), 120);
    CF_CHECK_LT(pub_y.size(), 120);
    CF_CHECK_LT(sig_v.size(), 120);
    CF_CHECK_LT(sig_w.size(), 120);
    CF_CHECK_LT(sig_x.size(), 120);
    CF_CHECK_LT(sig_y.size(), 120);

    RLC_TRY {
        fp_read_str(g1->x, pub_x.c_str(), pub_x.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g1->y, pub_y.c_str(), pub_y.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(g1->z, "1", 1, 10);

    RLC_TRY {
        fp_read_str(g2->x[0], sig_v.c_str(), sig_v.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->y[0], sig_w.c_str(), sig_w.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(g2->z[0], "1", 1, 10);

    RLC_TRY {
        fp_read_str(g2->x[1], sig_x.c_str(), sig_x.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(g2->y[1], sig_y.c_str(), sig_y.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(g2->z[1], "0", 1, 10);

    try {
        const auto pub = bls::G1Element::FromNative(g1);
        pub.CheckValid();
        const auto sig = bls::G2Element::FromNative(g2);
        sig.CheckValid();

        ret = bls::BasicSchemeMPL().Verify(pub, op.cleartext.Get(), sig);
    } catch ( ... ) {
        ret = false;
    }

end:
    g1_free(g1);
    g2_free(g2);

    return ret;
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

std::optional<component::G1> chia_bls::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    g1_t a, b;

    g1_new(a);
    g1_null(a);
    g1_new(b);
    g1_null(b);

    CF_CHECK_NE(op.a.first.ToTrimmedString(), "0");
    CF_CHECK_NE(op.a.second.ToTrimmedString(), "0");

    CF_CHECK_LT(op.a.first.ToTrimmedString().size(), 120);
    CF_CHECK_LT(op.a.second.ToTrimmedString().size(), 120);

    RLC_TRY {
        fp_read_str(a->x, op.a.first.ToTrimmedString().c_str(), op.a.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y, op.a.second.ToTrimmedString().c_str(), op.a.second.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z, "1", 1, 10);

    CF_CHECK_NE(op.b.first.ToTrimmedString(), "0");
    CF_CHECK_NE(op.b.second.ToTrimmedString(), "0");

    CF_CHECK_LT(op.b.first.ToTrimmedString().size(), 120);
    CF_CHECK_LT(op.b.second.ToTrimmedString().size(), 120);

    RLC_TRY {
        fp_read_str(b->x, op.b.first.ToTrimmedString().c_str(), op.b.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(b->y, op.b.second.ToTrimmedString().c_str(), op.b.second.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(b->z, "1", 1, 10);

    try {
        const auto A = bls::G1Element::FromNative(a);
        A.CheckValid();
        const auto B = bls::G1Element::FromNative(b);
        B.CheckValid();

        ret = chia_bls_detail::G1_To_Component(A + B);
    } catch ( ... ) {
    }

end:
    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    g1_t a;
    bn_t b;

    g1_new(a);
    g1_null(a);

    bn_new(b);
    bn_null(b);

    CF_CHECK_NE(op.a.first.ToTrimmedString(), "0");
    CF_CHECK_NE(op.a.second.ToTrimmedString(), "0");

    CF_CHECK_LT(op.a.first.ToTrimmedString().size(), 120);
    CF_CHECK_LT(op.a.second.ToTrimmedString().size(), 120);

    RLC_TRY {
        fp_read_str(a->x, op.a.first.ToTrimmedString().c_str(), op.a.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y, op.a.second.ToTrimmedString().c_str(), op.a.second.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z, "1", 1, 10);

    CF_CHECK_NE(op.b.ToTrimmedString(), "0");
    CF_CHECK_LT(op.b.ToTrimmedString().size(), 120);

    RLC_TRY {
        bn_read_str(b, op.b.ToTrimmedString().c_str(), op.b.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    try {
        const auto A = bls::G1Element::FromNative(a);
        A.CheckValid();

        ret = chia_bls_detail::G1_To_Component(A * b);
    } catch ( ... ) {
    }

end:
    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;

    g2_t a;
    bn_t b;

    g2_new(a);
    g2_null(a);

    bn_new(b);
    bn_null(b);

    const auto a_v = op.a.first.first.ToTrimmedString();
    const auto a_w = op.a.first.second.ToTrimmedString();
    const auto a_x = op.a.second.first.ToTrimmedString();
    const auto a_y = op.a.second.second.ToTrimmedString();

    CF_CHECK_NE(a_v, "0");
    CF_CHECK_NE(a_w, "0");
    CF_CHECK_NE(a_x, "0");
    CF_CHECK_NE(a_y, "0");

    CF_CHECK_LT(a_v.size(), 120);
    CF_CHECK_LT(a_w.size(), 120);
    CF_CHECK_LT(a_x.size(), 120);
    CF_CHECK_LT(a_y.size(), 120);

    RLC_TRY {
        fp_read_str(a->x[0], a_v.c_str(), a_v.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y[0], a_w.c_str(), a_w.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z[0], "1", 1, 10);

    RLC_TRY {
        fp_read_str(a->x[1], a_x.c_str(), a_x.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y[1], a_y.c_str(), a_y.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z[1], "0", 1, 10);

    CF_CHECK_NE(op.b.ToTrimmedString(), "0");
    CF_CHECK_LT(op.b.ToTrimmedString().size(), 120);

    RLC_TRY {
        bn_read_str(b, op.b.ToTrimmedString().c_str(), op.b.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    try {
        const auto A = bls::G2Element::FromNative(a);
        A.CheckValid();

        ret = chia_bls_detail::G2_To_Component(A * b);
    } catch ( ... ) {
    }

end:
    return ret;
}

std::optional<component::G1> chia_bls::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    g1_t a;

    g1_new(a);
    g1_null(a);

    CF_CHECK_NE(op.a.first.ToTrimmedString(), "0");
    CF_CHECK_NE(op.a.second.ToTrimmedString(), "0");

    CF_CHECK_LT(op.a.first.ToTrimmedString().size(), 120);
    CF_CHECK_LT(op.a.second.ToTrimmedString().size(), 120);

    RLC_TRY {
        fp_read_str(a->x, op.a.first.ToTrimmedString().c_str(), op.a.first.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y, op.a.second.ToTrimmedString().c_str(), op.a.second.ToTrimmedString().size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z, "1", 1, 10);

    try {
        const auto A = bls::G1Element::FromNative(a);
        A.CheckValid();

        ret = chia_bls_detail::G1_To_Component(A.Negate());
    } catch ( ... ) {
    }

end:
    return ret;
}

std::optional<component::G2> chia_bls::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;

    g2_t a;

    g2_new(a);
    g2_null(a);

    const auto a_v = op.a.first.first.ToTrimmedString();
    const auto a_w = op.a.first.second.ToTrimmedString();
    const auto a_x = op.a.second.first.ToTrimmedString();
    const auto a_y = op.a.second.second.ToTrimmedString();

    CF_CHECK_NE(a_v, "0");
    CF_CHECK_NE(a_w, "0");
    CF_CHECK_NE(a_x, "0");
    CF_CHECK_NE(a_y, "0");

    CF_CHECK_LT(a_v.size(), 120);
    CF_CHECK_LT(a_w.size(), 120);
    CF_CHECK_LT(a_x.size(), 120);
    CF_CHECK_LT(a_y.size(), 120);

    RLC_TRY {
        fp_read_str(a->x[0], a_v.c_str(), a_v.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y[0], a_w.c_str(), a_w.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z[0], "1", 1, 10);

    RLC_TRY {
        fp_read_str(a->x[1], a_x.c_str(), a_x.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    RLC_TRY {
        fp_read_str(a->y[1], a_y.c_str(), a_y.size(), 10);
    } RLC_CATCH_ANY {
        goto end;
    }

    fp_read_str(a->z[1], "0", 1, 10);

    try {
        const auto A = bls::G2Element::FromNative(a);
        A.CheckValid();

        ret = chia_bls_detail::G2_To_Component(A.Negate());
    } catch ( ... ) {
    }

end:
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
