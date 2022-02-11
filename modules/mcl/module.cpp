#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#if !defined(CRYPTOFUZZ_MCL_USE_BN128)
 #include <mcl/bls12_381.hpp>
#else
 #include <mcl/bn256.hpp>
#endif

#define MCL_DONT_USE_OPENSSL
#include <cybozu/sha2.hpp>

#if !defined(CRYPTOFUZZ_MCL_USE_BN128)
 #define Namespace ::mcl::bls12
#else
 #define Namespace ::mcl::bn
#endif

#include <iostream>
#include <vector>
#include <string>
#include <sstream>

namespace cryptofuzz {
namespace module {

mcl::mcl(void) :
    Module("mcl") {
#if !defined(CRYPTOFUZZ_MCL_USE_BN128)
        ::mcl::bn::initPairing(::mcl::BLS12_381);
        ::mcl::bn::setMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE_07);
#else
        ::mcl::bn::initPairing(::mcl::BN_SNARK1);
#endif
        CF_NORET(::mcl::bn::verifyOrderG1(1));
        CF_NORET(::mcl::bn::verifyOrderG2(1));
}

namespace mcl_detail {

std::vector<std::string> split(const std::string& s, std::optional<size_t> expectedNumParts = std::nullopt) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string tok;

    while (getline(ss, tok, ' ') ) {
        parts.push_back(tok);
    }

    if ( expectedNumParts != std::nullopt && parts.size() != *expectedNumParts ) {
        parts = std::vector<std::string>(*expectedNumParts, std::string("0"));
    }

    return parts;
}

/* "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_" */
    static const std::vector<uint8_t> DST{
        0x42, 0x4c, 0x53, 0x5f, 0x53, 0x49, 0x47, 0x5f, 0x42, 0x4c, 0x53, 0x31,
        0x32, 0x33, 0x38, 0x31, 0x47, 0x31, 0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53,
        0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f,
        0x52, 0x4f, 0x5f, 0x50, 0x4f, 0x50, 0x5f};

    template <class T>
    Buffer MsgAug(const T& op) {
        std::vector<uint8_t> msg;
        const auto aug = op.aug.Get();
        const auto ct = op.cleartext.Get();
        msg.insert(msg.end(), aug.begin(), aug.end());
        msg.insert(msg.end(), ct.begin(), ct.end());
        return Buffer(msg);
    }

    Namespace::G1 Convert(const component::G1& g1) {
        using namespace Namespace;
        return G1(
                Fp(g1.first.ToTrimmedString(), 10),
                Fp(g1.second.ToTrimmedString(), 10));
    }
    Namespace::G2 Convert(const component::G2& g2) {
        using namespace Namespace;
        return G2(
                {Fp(g2.first.first.ToTrimmedString(), 10), Fp(g2.second.first.ToTrimmedString(), 10)},
                {Fp(g2.first.second.ToTrimmedString(), 10), Fp(g2.second.second.ToTrimmedString(), 10)});
    }
    component::G1 ToComponentG1(Namespace::G1 g1) {
        /* Necessary? */
        g1.normalize();
        const auto parts = mcl_detail::split(g1.getStr(10), 3);
        return { parts[1], parts[2] };
    }

    component::G2 ToComponentG2(Namespace::G2 g2) {
        /* Necessary? */
        g2.normalize();
        const auto parts = mcl_detail::split(g2.getStr(10), 5);
        return { parts[1], parts[3], parts[2], parts[4] };
    }

    component::Fp2 ToComponentFp2(Namespace::Fp2 fp2) {
        const auto parts = mcl_detail::split(fp2.getStr(10), 2);
        return { parts[0], parts[1] };
    }

    component::Fp12 ToComponentFp12(Namespace::Fp12 fp12) {
        const auto parts = mcl_detail::split(fp12.getStr(10), 12);
        return {
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
            parts[6],
            parts[7],
            parts[8],
            parts[9],
            parts[10],
            parts[11],
        };
    }

    Namespace::G1 Generator(void) {
#if !defined(CRYPTOFUZZ_MCL_USE_BN128)
        return Namespace::G1(
                Namespace::Fp("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10),
                Namespace::Fp("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10) );
#else
        return Namespace::G1(
                Namespace::Fp("1", 10),
                Namespace::Fp("2", 10) );
#endif
    }

    Namespace::G2 Generator_G2(void) {
#if !defined(CRYPTOFUZZ_MCL_USE_BN128)
        return Namespace::G2(
                {Namespace::Fp("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", 10),
                Namespace::Fp("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758", 10)},
                {Namespace::Fp("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", 10),
                Namespace::Fp("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10)} );
#else
        return Namespace::G2(
                {Namespace::Fp("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10),
                Namespace::Fp("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)},
                {Namespace::Fp("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10),
                Namespace::Fp("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)} );
#endif
    }

    void Hash(Namespace::G1& P, const std::string& m)
    {
        Namespace::Fp t;
        t.setHashOf(m);
        Namespace::mapToG1(P, t);
    }

    void Hash(Namespace::G2& P, const std::string& m)
    {
        Namespace::Fp t;
        t.setHashOf(m);
        Namespace::mapToG2(P, Namespace::Fp2(t, 0));
    }

    void Sign(Namespace::G2& sign, const Namespace::Fr& s, const std::string& m)
    {
        Namespace::G2 Hm;
        Hash(Hm, m);
        Namespace::G2::mul(sign, Hm, s); // sign = s H(m)
    }

}

std::optional<component::Digest> mcl::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts = util::ToParts(ds, op.cleartext);

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("SHA256"):
            {
                cybozu::Sha256 hasher;
                for (const auto& part : parts) {
                    CF_NORET(hasher.update(part.first, part.second));
                }
                uint8_t out[256 / 8];
                CF_ASSERT(hasher.digest(out, sizeof(out), nullptr, 0) == sizeof(out), "Unexpected digest() output");
                ret = {out, sizeof(out)};
            }
            break;
        case    CF_DIGEST("SHA512"):
            {
                cybozu::Sha512 hasher;
                for (const auto& part : parts) {
                    CF_NORET(hasher.update(part.first, part.second));
                }
                uint8_t out[512 / 8];
                CF_ASSERT(hasher.digest(out, sizeof(out), nullptr, 0) == sizeof(out), "Unexpected digest() output");
                ret = {out, sizeof(out)};
            }
            break;
    }

    return ret;
}

std::optional<component::BLS_PublicKey> mcl::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    std::optional<component::BLS_PublicKey> ret = std::nullopt;

    if ( op.priv.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    try {
        using namespace Namespace;

        Fr sec;
        sec.setStr(op.priv.ToTrimmedString(), 10);

        G1 pub;
        G1::mul(pub, mcl_detail::Generator(), sec);

        ret = mcl_detail::ToComponentG1(pub);
    } catch ( cybozu::Exception ) {
        if ( !op.priv.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184512") ) {
            CF_ASSERT(0, "Failed to sign");
        }
    }

    return ret;
}

std::optional<component::G2> mcl::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.priv.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    try {
        using namespace Namespace;

        Fr sec;
        sec.setStr(op.priv.ToTrimmedString(), 10);

        G2 pub;
        G2::mul(pub, mcl_detail::Generator_G2(), sec);

        ret = mcl_detail::ToComponentG2(pub);
    } catch ( cybozu::Exception ) {
        if ( !op.priv.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184512") ) {
            CF_ASSERT(0, "Failed to sign");
        }
    }

    return ret;
}

std::optional<component::BLS_Signature> mcl::OpBLS_Sign(operation::BLS_Sign& op) {
    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.priv.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    try {
        using namespace Namespace;
        Fr sec;
        sec.setStr(op.priv.ToTrimmedString(), 10);

        G2 sign;
        if ( op.hashOrPoint == true ) {
            G2 hash;
            const auto msg = mcl_detail::MsgAug(op);
            BN::param.mapTo.mapTo_WB19_.msgToG2(hash, msg.GetPtr(&ds), msg.GetSize(), (const char*)op.dest.GetPtr(&ds), op.dest.GetSize());
            Namespace::G2::mul(sign, hash, sec);
        } else {
            const auto g2 = mcl_detail::Convert(op.point);
            Namespace::G2::mul(sign, g2, sec);
        }

        G1 pub;
        G1::mul(pub, mcl_detail::Generator(), sec);

        ret = { mcl_detail::ToComponentG2(sign), mcl_detail::ToComponentG1(pub) };
    } catch ( cybozu::Exception ) {
        /* Failing is acceptable if:
         *
         * - An (invalid) point was tried to sign
         * - Tried to sign with an invalid private key
         *
         * Abort otherwise
         */
        if ( op.hashOrPoint ) {
            if ( !op.priv.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184512") ) {
                CF_ASSERT(0, "Failed to sign");
            }
        }
    }

    return ret;
}

std::optional<bool> mcl::OpBLS_Verify(operation::BLS_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.dest.Get() != mcl_detail::DST ) {
        return std::nullopt;
    }

    try {
        using namespace Namespace;
        const auto pub = mcl_detail::Convert(op.pub);
        const auto signature = mcl_detail::Convert(op.signature);

        G2 Q;
        mapToG2(Q, 1);

        //ret = mcl_detail::Verify(signature, Q, pub, std::string(op.cleartext.GetPtr(), op.cleartext.GetPtr() + op.cleartext.GetSize()));
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<bool> mcl::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    Namespace::Fp12 f;
    f.setOne();

    try {
        for (const auto& cur : op.bf.c) {
            const auto g1 = mcl_detail::Convert(cur.g1);
            CF_CHECK_TRUE(g1.isValid());

            const auto g2 = mcl_detail::Convert(cur.g2);
            CF_CHECK_TRUE(g2.isValid());

            Namespace::Fp12 tmp;
            Namespace::millerLoop(tmp, g1, g2);
            f *= tmp;
        }
    } catch ( ... ) {
        goto end;
    }

    Namespace::finalExp(f, f);

    ret = f.isOne();
end:
    return ret;
}

std::optional<component::Fp12> mcl::OpBLS_Pairing(operation::BLS_Pairing& op) {
    std::optional<component::Fp12> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        using namespace Namespace;

        const auto g1 = mcl_detail::Convert(op.g1);
        //CF_CHECK_TRUE(g1.isValid());

        const auto g2 = mcl_detail::Convert(op.g2);
        //CF_CHECK_TRUE(g2.isValid());

        Fp12 f;

        bool precompute = false;
        try {
            precompute = ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        if ( precompute == true ) {
            std::vector<Fp6> Qcoeff;
            precomputeG2(Qcoeff, g2);
            precomputedMillerLoop(f, g1, Qcoeff);
        } else {
            millerLoop(f, g1, g2);
        }

        finalExp(f, f);

        ret = mcl_detail::ToComponentFp12(f);

    } catch ( cybozu::Exception ) {
    }

end:
    return ret;
}

std::optional<component::Fp12> mcl::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    std::optional<component::Fp12> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        using namespace Namespace;

        auto f = ::mcl::bn::Fp12(
                ::mcl::bn::Fp6(
                    ::mcl::bn::Fp2(
                        op.fp12.bn1.ToTrimmedString(),
                        op.fp12.bn2.ToTrimmedString()
                        ),
                    ::mcl::bn::Fp2(
                        op.fp12.bn3.ToTrimmedString(),
                        op.fp12.bn4.ToTrimmedString()
                        ),
                    ::mcl::bn::Fp2(
                        op.fp12.bn5.ToTrimmedString(),
                        op.fp12.bn6.ToTrimmedString()
                        )
                    ),
                ::mcl::bn::Fp6(
                    ::mcl::bn::Fp2(
                        op.fp12.bn7.ToTrimmedString(),
                        op.fp12.bn8.ToTrimmedString()
                        ),
                    ::mcl::bn::Fp2(
                        op.fp12.bn9.ToTrimmedString(),
                        op.fp12.bn10.ToTrimmedString()
                        ),
                    ::mcl::bn::Fp2(
                        op.fp12.bn11.ToTrimmedString(),
                        op.fp12.bn12.ToTrimmedString()
                        )
                    )
        );

        //::mcl::bn::Fp12::unitaryInv(f, f);
        finalExp(f, f);

        ret = mcl_detail::ToComponentFp12(f);
    } catch ( cybozu::Exception ) {
    }

end:
    return ret;
}

std::optional<bool> mcl::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    using namespace Namespace;

    Namespace::Fp x, y;

    try {
        x = Fp(op.g1.first.ToTrimmedString(), 10);
        y = Fp(op.g1.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        return Namespace::G1(x, y).isValid();
    } catch ( cybozu::Exception ) {
        return false;
    }
}

std::optional<bool> mcl::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    using namespace Namespace;

    Namespace::Fp x1, y1, x2, y2;

    try {
        x1 = Fp(op.g2.first.first.ToTrimmedString(), 10);
        y1 = Fp(op.g2.second.first.ToTrimmedString(), 10);
        x2 = Fp(op.g2.first.second.ToTrimmedString(), 10);
        y2 = Fp(op.g2.second.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        return Namespace::G2({x1, y1}, {x2, y2}).isValid();
    } catch ( cybozu::Exception ) {
        return false;
    }
}

std::optional<component::G1> mcl::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    using namespace Namespace;
    G1 P;
    const auto msg = mcl_detail::MsgAug(op);
    BN::param.mapTo.mapTo_WB19_.msgToG1(P, msg.GetPtr(&ds), msg.GetSize(), (const char*)op.dest.GetPtr(&ds), op.dest.GetSize());

    /* Alternative: requires that op.dest == mcl_detail::DST */
    ///* noret */ hashAndMapToG1(P, msg.data(), msg.size());
    ret = mcl_detail::ToComponentG1(P);

    return ret;
}

std::optional<component::G2> mcl::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    using namespace Namespace;
    G2 P;
    const auto msg = mcl_detail::MsgAug(op);
    BN::param.mapTo.mapTo_WB19_.msgToG2(P, msg.GetPtr(&ds), msg.GetSize(), (const char*)op.dest.GetPtr(&ds), op.dest.GetSize());

    /* Alternative: requires that op.dest == mcl_detail::DST */
    ///* noret */ hashAndMapToG2(P, msg.data(), msg.size());
    ret = mcl_detail::ToComponentG2(P);

    return ret;
}

std::optional<component::G1> mcl::OpBLS_MapToG1(operation::BLS_MapToG1& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    using namespace Namespace;
    G1 P;
    ::mcl::bn::Fp u, v;
    try {
        u.setStr(op.u.ToTrimmedString(), 10);
        v.setStr(op.v.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        goto end;
    }
    CF_NORET(BN::param.mapTo.mapTo_WB19_.FpToG1(P, u, &v));

    if ( !P.isValid() ) {
        ret = component::G1{"0", "0"};
    } else {
        ret = mcl_detail::ToComponentG1(P);
    }

end:
    return ret;
}

std::optional<component::G2> mcl::OpBLS_MapToG2(operation::BLS_MapToG2& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    using namespace Namespace;
    G2 P;
    ::mcl::bn::Fp2 u, v;
    try {
        u = ::mcl::bn::Fp2(
                op.u.first.ToTrimmedString(),
                op.u.second.ToTrimmedString());
        v = ::mcl::bn::Fp2(
                op.v.first.ToTrimmedString(),
                op.v.second.ToTrimmedString());
    } catch ( cybozu::Exception ) {
        goto end;
    }
    CF_NORET(BN::param.mapTo.mapTo_WB19_.Fp2ToG2(P, u, &v));

    if ( !P.isValid() ) {
        ret = { "0", "0", "0", "0" };
    } else {
        ret = mcl_detail::ToComponentG2(P);
    }

end:
    return ret;
}

std::optional<component::G1> mcl::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_x, a_y, b_x, b_y;

    try {
        a_x = Fp(op.a.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.ToTrimmedString(), 10);
        b_x = Fp(op.b.first.ToTrimmedString(), 10);
        b_y = Fp(op.b.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G1(a_x, a_y);
        const auto b = Namespace::G1(b_x, b_y);

        const auto result = a + b;

        ret = mcl_detail::ToComponentG1(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<component::G1> mcl::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_x, a_y;
    Namespace::Fp b;

    try {
        a_x = Fp(op.a.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.ToTrimmedString(), 10);

        b = Fp(op.b.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G1(a_x, a_y);

        const auto result = a * b;

        ret = mcl_detail::ToComponentG1(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<bool> mcl::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    std::optional<bool> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_x, a_y, b_x, b_y;

    try {
        a_x = Fp(op.a.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.ToTrimmedString(), 10);
        b_x = Fp(op.b.first.ToTrimmedString(), 10);
        b_y = Fp(op.b.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G1(a_x, a_y);
        const auto b = Namespace::G1(b_x, b_y);

        ret = a == b;
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<component::G1> mcl::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_x, a_y;

    try {
        a_x = Fp(op.a.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G1(a_x, a_y);

        const auto result = -a;

        ret = mcl_detail::ToComponentG1(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<component::G2> mcl::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    std::optional<component::G2> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_v, a_w, a_x, a_y;
    Namespace::Fp b_v, b_w, b_x, b_y;

    try {
        a_v = Fp(op.a.first.first.ToTrimmedString(), 10);
        a_w = Fp(op.a.first.second.ToTrimmedString(), 10);
        a_x = Fp(op.a.second.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.second.ToTrimmedString(), 10);

        b_v = Fp(op.b.first.first.ToTrimmedString(), 10);
        b_w = Fp(op.b.first.second.ToTrimmedString(), 10);
        b_x = Fp(op.b.second.first.ToTrimmedString(), 10);
        b_y = Fp(op.b.second.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G2({a_v, a_x}, {a_w, a_y});
        const auto b = Namespace::G2({b_v, b_x}, {b_w, b_y});

        const auto result = a + b;

        ret = mcl_detail::ToComponentG2(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<component::G2> mcl::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_v, a_w, a_x, a_y;
    Namespace::Fp b;

    try {
        a_v = Fp(op.a.first.first.ToTrimmedString(), 10);
        a_w = Fp(op.a.first.second.ToTrimmedString(), 10);
        a_x = Fp(op.a.second.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.second.ToTrimmedString(), 10);

        b = Fp(op.b.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G2({a_v, a_x}, {a_w, a_y});

        const auto result = a * b;

        ret = mcl_detail::ToComponentG2(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<bool> mcl::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    std::optional<bool> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_v, a_w, a_x, a_y;
    Namespace::Fp b_v, b_w, b_x, b_y;

    try {
        a_v = Fp(op.a.first.first.ToTrimmedString(), 10);
        a_w = Fp(op.a.first.second.ToTrimmedString(), 10);
        a_x = Fp(op.a.second.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.second.ToTrimmedString(), 10);

        b_v = Fp(op.b.first.first.ToTrimmedString(), 10);
        b_w = Fp(op.b.first.second.ToTrimmedString(), 10);
        b_x = Fp(op.b.second.first.ToTrimmedString(), 10);
        b_y = Fp(op.b.second.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G2({a_v, a_x}, {a_w, a_y});
        const auto b = Namespace::G2({b_v, b_x}, {b_w, b_y});

        ret = a == b;
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

std::optional<component::G2> mcl::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;
    using namespace Namespace;

    Namespace::Fp a_v, a_w, a_x, a_y;

    try {
        a_v = Fp(op.a.first.first.ToTrimmedString(), 10);
        a_w = Fp(op.a.first.second.ToTrimmedString(), 10);
        a_x = Fp(op.a.second.first.ToTrimmedString(), 10);
        a_y = Fp(op.a.second.second.ToTrimmedString(), 10);
    } catch ( cybozu::Exception ) {
        /* May throw exception if string represents value larger than curve order */
        return std::nullopt;
    }

    try {
        const auto a = Namespace::G2({a_v, a_x}, {a_w, a_y});

        const auto result = -a;

        ret = mcl_detail::ToComponentG2(result);
    } catch ( cybozu::Exception ) {
        return std::nullopt;
    }

    return ret;
}

namespace mcl_detail {
    template <class T>
    bool UseParamTwice(fuzzing::datasource::Datasource& ds, const T& A, const T& B) {
        if ( A != B ) {
            return false;
        }

        try {
            return ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return false;
    }

    uint8_t GetMod3(fuzzing::datasource::Datasource& ds) {
        try {
            return ds.Get<uint8_t>() % 3;
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return 0;
    }
}

std::optional<component::Bignum> mcl::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

#define PREPARE_BN() { \
    ap = &a; bp = mcl_detail::UseParamTwice(ds, a, b) ? &a : &b; \
    switch ( mcl_detail::GetMod3(ds) ) { \
        case    0: \
            resultp = &a; \
            break; \
        case    1: \
            resultp = &b; \
            break; \
        case    2: \
            resultp = &result; \
            break; \
    } \
}

    /* TODO optimize this */
    if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        ::mcl::bn::Fr a, b, result;
        ::mcl::bn::Fr* ap, *bp, *resultp;

        try {
            switch ( op.calcOp.Get() ) {
                case    CF_CALCOP("Add(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return (*ap+*bp).getStr();
                case    CF_CALCOP("Sub(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return (*ap-*bp).getStr();
                case    CF_CALCOP("Mul(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return ((*ap)*(*bp)).getStr();
                case    CF_CALCOP("InvMod(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        CF_CHECK_NE(a, b);
                        PREPARE_BN();
                        ::mcl::bn::Fr::inv(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqr(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::sqr(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Not(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::neg(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("LShift1(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::mul2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("IsEq(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap == *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsGt(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap > *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsGte(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap >= *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsLt(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap < *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsLte(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap <= *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsZero(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 0 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOne(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 1 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOdd(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsEven(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("0") : std::string("1");
                    }
                case    CF_CALCOP("Sqrt(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        if ( ::mcl::bn::Fr::squareRoot(*resultp, *ap) == false ) {
                            return std::string("0");
                        }
                        ::mcl::bn::Fr::sqr(*resultp, *resultp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Exp(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::pow(*resultp, *ap, *bp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Cmp(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        if ( *ap == *bp ) {
                            return std::string("0");
                        } else if ( *ap < *bp ) {
                            return std::string("-1");
                        } else if ( *ap > *bp ) {
                            return std::string("1");
                        } else {
                            CF_UNREACHABLE();
                        }
                    }
                case    CF_CALCOP("Set(A)"):
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        return a.getStr();
            }
        } catch ( cybozu::Exception ) {
            if (
                    !op.bn0.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184511") &&
                    !op.bn1.IsGreaterThan("52435875175126190479447740508185965837690552500527637822603658699938581184511") ) {
                CF_ASSERT(0, "BignumCalc_Mod_BLS12_381_R unexpectedly failed");
            }
        }

        return std::nullopt;
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        ::mcl::bn::Fp a, b, result;
        ::mcl::bn::Fp* ap, *bp, *resultp;

        try {
            switch ( op.calcOp.Get() ) {
                case    CF_CALCOP("Add(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return (*ap+*bp).getStr();
                case    CF_CALCOP("Sub(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return (*ap-*bp).getStr();
                case    CF_CALCOP("Mul(A,B)"):
                    a.setStr(op.bn0.ToTrimmedString(), 10);
                    b.setStr(op.bn1.ToTrimmedString(), 10);
                    PREPARE_BN();
                    return ((*ap)*(*bp)).getStr();
                case    CF_CALCOP("InvMod(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        CF_CHECK_NE(a, b);
                        PREPARE_BN();
                        ::mcl::bn::Fp::inv(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqr(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::sqr(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Not(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::neg(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("LShift1(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::mul2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("IsEq(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap == *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsGt(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap > *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsGte(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap >= *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsLt(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap < *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsLte(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        return *ap <= *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsZero(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 0 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOne(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 1 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOdd(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsEven(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("0") : std::string("1");
                    }
                case    CF_CALCOP("RShift(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        if ( *bp != 1 ) {
                            return std::nullopt;
                        }
                        ::mcl::bn::Fp::divBy2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqrt(A)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        if ( ::mcl::bn::Fp::squareRoot(*resultp, *ap) == false ) {
                            return std::string("0");
                        }
                        ::mcl::bn::Fp::sqr(*resultp, *resultp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Exp(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::pow(*resultp, *ap, *bp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Cmp(A,B)"):
                    {
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        b.setStr(op.bn1.ToTrimmedString(), 10);
                        PREPARE_BN();
                        if ( *ap == *bp ) {
                            return std::string("0");
                        } else if ( *ap < *bp ) {
                            return std::string("-1");
                        } else if ( *ap > *bp ) {
                            return std::string("1");
                        } else {
                            CF_UNREACHABLE();
                        }
                    }
                case    CF_CALCOP("Set(A)"):
                        a.setStr(op.bn0.ToTrimmedString(), 10);
                        return a.getStr();
            }
        } catch ( cybozu::Exception ) {
            if (
                    !op.bn0.IsGreaterThan("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786") &&
                    !op.bn1.IsGreaterThan("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786") ) {
                CF_ASSERT(0, "BignumCalc_Mod_BLS12_381_P unexpectedly failed");
            }
        }

        return std::nullopt;
    }

end:
        return std::nullopt;
}

std::optional<component::Fp2> mcl::OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) {
    ::mcl::bn::Fp2 a, b, result;
    ::mcl::bn::Fp* ap, *bp, *resultp;

    try {
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                b = ::mcl::bn::Fp2(
                        op.bn1.first.ToTrimmedString(),
                        op.bn1.second.ToTrimmedString());

                return mcl_detail::ToComponentFp2(a+b);
            case    CF_CALCOP("Sub(A,B)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                b = ::mcl::bn::Fp2(
                        op.bn1.first.ToTrimmedString(),
                        op.bn1.second.ToTrimmedString());

                return mcl_detail::ToComponentFp2(a-b);
            case    CF_CALCOP("Mul(A,B)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                b = ::mcl::bn::Fp2(
                        op.bn1.first.ToTrimmedString(),
                        op.bn1.second.ToTrimmedString());

                return mcl_detail::ToComponentFp2(a*b);
            case    CF_CALCOP("InvMod(A,B)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());

                if ( !a.isZero() ) {
                    ::mcl::bn::Fp2::inv(result, a);
                    return mcl_detail::ToComponentFp2(result);
                }
                break;
            case    CF_CALCOP("Sqrt(A)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                if ( ::mcl::bn::Fp2::squareRoot(result, a) == false ) {
                    return component::Fp2{"0", "0"};
                } else {
                    ::mcl::bn::Fp2::sqr(result, result);
                    return mcl_detail::ToComponentFp2(result);
                }
            case    CF_CALCOP("Neg(A)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                ::mcl::bn::Fp2::neg(result, a);
                return mcl_detail::ToComponentFp2(result);
            case    CF_CALCOP("Sqr(A)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                ::mcl::bn::Fp2::sqr(result, a);
                return mcl_detail::ToComponentFp2(result);
            case    CF_CALCOP("LShift1(A)"):
                a = ::mcl::bn::Fp2(
                        op.bn0.first.ToTrimmedString(),
                        op.bn0.second.ToTrimmedString());
                ::mcl::bn::Fp2::mul2(result, a);
                return mcl_detail::ToComponentFp2(result);
        }
    } catch ( ... ) {
    }

    return std::nullopt;
}

std::optional<component::Fp12> mcl::OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) {
    ::mcl::bn::Fp12 a, b, result;
    ::mcl::bn::Fp* ap, *bp, *resultp;

    try {
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                b = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn1.ToTrimmedString(),
                                op.bn1.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn3.ToTrimmedString(),
                                op.bn1.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn5.ToTrimmedString(),
                                op.bn1.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn7.ToTrimmedString(),
                                op.bn1.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn9.ToTrimmedString(),
                                op.bn1.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn11.ToTrimmedString(),
                                op.bn1.bn12.ToTrimmedString()
                            )
                        )
                    );
                return mcl_detail::ToComponentFp12(a+b);
            case    CF_CALCOP("Sub(A,B)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                b = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn1.ToTrimmedString(),
                                op.bn1.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn3.ToTrimmedString(),
                                op.bn1.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn5.ToTrimmedString(),
                                op.bn1.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn7.ToTrimmedString(),
                                op.bn1.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn9.ToTrimmedString(),
                                op.bn1.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn11.ToTrimmedString(),
                                op.bn1.bn12.ToTrimmedString()
                            )
                        )
                    );
                return mcl_detail::ToComponentFp12(a-b);
            case    CF_CALCOP("Mul(A,B)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                b = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn1.ToTrimmedString(),
                                op.bn1.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn3.ToTrimmedString(),
                                op.bn1.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn5.ToTrimmedString(),
                                op.bn1.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn1.bn7.ToTrimmedString(),
                                op.bn1.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn9.ToTrimmedString(),
                                op.bn1.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn1.bn11.ToTrimmedString(),
                                op.bn1.bn12.ToTrimmedString()
                            )
                        )
                    );
                return mcl_detail::ToComponentFp12(a*b);
            case    CF_CALCOP("InvMod(A,B)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );

                if ( !a.isZero() ) {
                    ::mcl::bn::Fp12::inv(result, a);
                    return mcl_detail::ToComponentFp12(result);
                }
                break;
            case    CF_CALCOP("Neg(A)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                ::mcl::bn::Fp12::neg(result, a);
                return mcl_detail::ToComponentFp12(result);
            case    CF_CALCOP("Conjugate(A)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                ::mcl::bn::Fp12::unitaryInv(result, a);
                return mcl_detail::ToComponentFp12(result);
            case    CF_CALCOP("Sqr(A)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                ::mcl::bn::Fp12::sqr(result, a);
                return mcl_detail::ToComponentFp12(result);
#if 0
            case    CF_CALCOP("CyclotomicSqr(A)"):
                a = ::mcl::bn::Fp12(
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn1.ToTrimmedString(),
                                op.bn0.bn2.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn3.ToTrimmedString(),
                                op.bn0.bn4.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn5.ToTrimmedString(),
                                op.bn0.bn6.ToTrimmedString()
                            )
                        ),
                        ::mcl::bn::Fp6(
                            ::mcl::bn::Fp2(
                                op.bn0.bn7.ToTrimmedString(),
                                op.bn0.bn8.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn9.ToTrimmedString(),
                                op.bn0.bn10.ToTrimmedString()
                            ),
                            ::mcl::bn::Fp2(
                                op.bn0.bn11.ToTrimmedString(),
                                op.bn0.bn12.ToTrimmedString()
                            )
                        )
                    );
                if ( !a.isZero() ) {
                    ::mcl::bn::local::mapToCyclotomic(result, a);
                    return mcl_detail::ToComponentFp12(result);
                }
                break;
#endif
        }
    } catch ( ... ) {
    }

    return std::nullopt;
}

bool mcl::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
