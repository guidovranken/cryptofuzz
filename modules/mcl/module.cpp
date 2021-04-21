#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include <mcl/bls12_381.hpp>
#define MCL_DONT_USE_OPENSSL
#include <cybozu/sha2.hpp>

#include <iostream>
#include <vector>
#include <string>
#include <sstream>

namespace cryptofuzz {
namespace module {

mcl::mcl(void) :
    Module("mcl") {
        ::mcl::bn::initPairing(::mcl::BLS12_381);
        ::mcl::bn::setMapToMode(MCL_MAP_TO_MODE_HASH_TO_CURVE_07);
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
        printf("parts.size(): %zu, expected: %zu\n", parts.size(), *expectedNumParts);
        abort();
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
    std::vector<uint8_t> MsgAug(const T& op) {
        std::vector<uint8_t> msg;
        const auto aug = op.aug.Get();
        const auto ct = op.cleartext.Get();
        msg.insert(msg.end(), aug.begin(), aug.end());
        msg.insert(msg.end(), ct.begin(), ct.end());
        return msg;
    }

    ::mcl::bls12::G1 Convert(const component::G1& g1) {
        using namespace ::mcl::bls12;
        return G1(
                Fp(g1.first.ToTrimmedString(), 10),
                Fp(g1.second.ToTrimmedString(), 10));
    }
    ::mcl::bls12::G2 Convert(const component::G2& g2) {
        using namespace ::mcl::bls12;
        return G2(
                {Fp(g2.first.first.ToTrimmedString(), 10), Fp(g2.second.first.ToTrimmedString(), 10)},
                {Fp(g2.first.second.ToTrimmedString(), 10), Fp(g2.second.second.ToTrimmedString(), 10)});
    }
    component::G1 ToComponentG1(::mcl::bls12::G1 g1) {
        /* Necessary? */
        g1.normalize();
        const auto parts = mcl_detail::split(g1.getStr(10), 3);
        return { parts[1], parts[2] };
    }

    component::G2 ToComponentG2(::mcl::bls12::G2 g2) {
        /* Necessary? */
        g2.normalize();
        const auto parts = mcl_detail::split(g2.getStr(10), 5);
        return { parts[1], parts[3], parts[2], parts[4] };
    }

    ::mcl::bls12::G1 Generator(void) {
        return ::mcl::bls12::G1(
                ::mcl::bls12::Fp("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10),
                ::mcl::bls12::Fp("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10) );
    }

    void Hash(::mcl::bls12::G1& P, const std::string& m)
    {
        ::mcl::bls12::Fp t;
        t.setHashOf(m);
        ::mcl::bls12::mapToG1(P, t);
    }

    void Hash(::mcl::bls12::G2& P, const std::string& m)
    {
        ::mcl::bls12::Fp t;
        t.setHashOf(m);
        ::mcl::bls12::mapToG2(P, ::mcl::bls12::Fp2(t, 0));
    }

    void Sign(::mcl::bls12::G2& sign, const ::mcl::bls12::Fr& s, const std::string& m)
    {
        ::mcl::bls12::G2 Hm;
        Hash(Hm, m);
        ::mcl::bls12::G2::mul(sign, Hm, s); // sign = s H(m)
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
        using namespace ::mcl::bls12;

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

std::optional<component::BLS_Signature> mcl::OpBLS_Sign(operation::BLS_Sign& op) {
    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.priv.ToTrimmedString() == "0" ) {
        return std::nullopt;
    }

    try {
        using namespace ::mcl::bls12;
        Fr sec;
        sec.setStr(op.priv.ToString(ds), 10);

        G2 sign;
        if ( op.hashOrPoint == true ) {
            G2 hash;
            const auto msg = mcl_detail::MsgAug(op);
            BN::param.mapTo.mapTo_WB19_.msgToG2(hash, msg.data(), msg.size(), (const char*)op.dest.GetPtr(), op.dest.GetSize());
            ::mcl::bls12::G2::mul(sign, hash, sec);
        } else {
            const auto g2 = mcl_detail::Convert(op.point);
            ::mcl::bls12::G2::mul(sign, g2, sec);
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
        using namespace ::mcl::bls12;
        const auto pub = mcl_detail::Convert(op.pub);
        const auto signature = mcl_detail::Convert(op.signature);

        G2 Q;
        mapToG2(Q, 1);

        //ret = mcl_detail::Verify(signature, Q, pub, std::string(op.cleartext.GetPtr(), op.cleartext.GetPtr() + op.cleartext.GetSize()));
    } catch ( cybozu::Exception ) { }

    return ret;
}

std::optional<bool> mcl::OpBLS_Pairing(operation::BLS_Pairing& op) {
#if 0
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        G1 P;
        G2 Q;
        if ( op.hashInput != std::nullopt ) {
            {
                auto blsHashToG1Modifier = ds.GetData(0);
                operation::BLS_HashToG1 opBLSHashToG1(
                        op.curveType,
                        *op.hashInput,
                        component::Modifier(blsHashToG1Modifier.data(), blsHashToG1Modifier.size()));

                auto p = OpBLS_HashToG1(opBLSHashToG1);
                if ( p == std::nullopt ) {
                    return std::nullopt;
                }

                P = G1(
                        Fp(p->first.ToString(ds), 10),
                        Fp(p->second.ToString(ds), 10));
            }

            {
                auto blsHashToG2Modifier = ds.GetData(0);
                operation::BLS_HashToG2 opBLSHashToG2(
                        op.curveType,
                        *op.hashInput,
                        component::Modifier(blsHashToG2Modifier.data(), blsHashToG2Modifier.size()));

                auto q = OpBLS_HashToG2(opBLSHashToG2);
                if ( q == std::nullopt ) {
                    return std::nullopt;
                }

                Q = G2(
                        Fp2(q->first.first.ToString(ds), q->first.second.ToString(ds), 10),
                        Fp2(q->second.first.ToString(ds), q->second.second.ToString(ds), 10));
            }

        } else {
            P = G1(
                    Fp(op.q.first.ToString(ds), 10),
                    Fp(op.q.second.ToString(ds), 10));
            Q = G2(
                    Fp2(op.p.first.first.ToString(ds), op.p.first.second.ToString(ds), 10),
                    Fp2(op.p.second.first.ToString(ds), op.p.second.second.ToString(ds), 10));
        }

        Fp12 f;
        pairing(f, P, Q);
        const auto parts = mcl_detail::split(f.getStr(10), 12);
    }
    catch ( cybozu::Exception ) { }
    catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return ret;
#endif
    return std::nullopt;
}

std::optional<bool> mcl::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    if (
            (op.g1.first.ToTrimmedString() == "0" || op.g1.first.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") &&
            (op.g1.second.ToTrimmedString() == "0" || op.g1.second.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") ) {
        /* Same behavior as blst */
        return true;
    }

    using namespace ::mcl::bls12;

    try {
        return mcl_detail::Convert(op.g1).isValid();
    } catch ( cybozu::Exception ) {
        return false;
    }

    return std::nullopt;
}

std::optional<bool> mcl::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    if (
            (op.g2.first.first.ToTrimmedString() == "0" || op.g2.first.first.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") &&
            (op.g2.first.second.ToTrimmedString() == "0" || op.g2.first.second.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") &&
            (op.g2.second.first.ToTrimmedString() == "0" || op.g2.second.first.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") &&
            (op.g2.second.second.ToTrimmedString() == "0" || op.g2.second.second.ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787") ) {
        /* Same behavior as blst */
        return true;
    }

    using namespace ::mcl::bls12;

    try {
        return mcl_detail::Convert(op.g2).isValid();
    } catch ( cybozu::Exception ) {
        return false;
    }

    return std::nullopt;
}

std::optional<component::G1> mcl::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;

    using namespace ::mcl::bls12;
    G1 P;
    const auto msg = mcl_detail::MsgAug(op);
    BN::param.mapTo.mapTo_WB19_.msgToG1(P, msg.data(), msg.size(), (const char*)op.dest.GetPtr(), op.dest.GetSize());

    /* Alternative: requires that op.dest == mcl_detail::DST */
    ///* noret */ hashAndMapToG1(P, msg.data(), msg.size());
    ret = mcl_detail::ToComponentG1(P);

    return ret;
}

std::optional<component::G2> mcl::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;

    using namespace ::mcl::bls12;
    G2 P;
    const auto msg = mcl_detail::MsgAug(op);
    BN::param.mapTo.mapTo_WB19_.msgToG2(P, msg.data(), msg.size(), (const char*)op.dest.GetPtr(), op.dest.GetSize());

    /* Alternative: requires that op.dest == mcl_detail::DST */
    ///* noret */ hashAndMapToG2(P, msg.data(), msg.size());
    ret = mcl_detail::ToComponentG2(P);

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
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return (*ap+*bp).getStr();
                case    CF_CALCOP("Sub(A,B)"):
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return (*ap-*bp).getStr();
                case    CF_CALCOP("Mul(A,B)"):
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return ((*ap)*(*bp)).getStr();
                case    CF_CALCOP("InvMod(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::inv(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqr(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::sqr(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Not(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::neg(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("LShift1(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::mul2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("IsEq(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
                        PREPARE_BN();
                        return *ap == *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsZero(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 0 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOne(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 1 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOdd(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsEven(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("0") : std::string("1");
                    }
                case    CF_CALCOP("Sqrt(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::squareRoot(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Exp(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
                        PREPARE_BN();
                        ::mcl::bn::Fr::pow(*resultp, *ap, *bp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Cmp(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
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
                        a.setStr(op.bn0.ToString(ds), 10);
                        return a.getStr();
            }
        } catch ( cybozu::Exception ) { }

        return std::nullopt;
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        ::mcl::bn::Fp a, b, result;
        ::mcl::bn::Fp* ap, *bp, *resultp;

        try {
            switch ( op.calcOp.Get() ) {
                case    CF_CALCOP("Add(A,B)"):
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return (*ap+*bp).getStr();
                case    CF_CALCOP("Sub(A,B)"):
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return (*ap-*bp).getStr();
                case    CF_CALCOP("Mul(A,B)"):
                    a.setStr(op.bn0.ToString(ds), 10);
                    b.setStr(op.bn1.ToString(ds), 10);
                    PREPARE_BN();
                    return ((*ap)*(*bp)).getStr();
                case    CF_CALCOP("InvMod(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::inv(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqr(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::sqr(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Not(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::neg(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("LShift1(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::mul2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("IsEq(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
                        PREPARE_BN();
                        return *ap == *bp ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsZero(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 0 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOne(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return *ap == 1 ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsOdd(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("1") : std::string("0");
                    }
                case    CF_CALCOP("IsEven(A)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        return ap->isOdd() ? std::string("0") : std::string("1");
                    }
                case    CF_CALCOP("RShift(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
                        PREPARE_BN();
                        if ( *bp != 1 ) {
                            return std::nullopt;
                        }
                        ::mcl::bn::Fp::divBy2(*resultp, *ap);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Sqrt(A)"):
                    {
                        /* Compute the sqrt but don't return it, because blst may return
                         * a different (but also valid) result
                         */
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr("0", 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::squareRoot(*resultp, *ap);
                        return std::nullopt;
                        //return resultp->getStr();
                    }
                case    CF_CALCOP("Exp(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
                        PREPARE_BN();
                        ::mcl::bn::Fp::pow(*resultp, *ap, *bp);
                        return resultp->getStr();
                    }
                case    CF_CALCOP("Cmp(A,B)"):
                    {
                        a.setStr(op.bn0.ToString(ds), 10);
                        b.setStr(op.bn1.ToString(ds), 10);
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
                        a.setStr(op.bn0.ToString(ds), 10);
                        return a.getStr();
            }
        } catch ( cybozu::Exception ) { }
        return std::nullopt;
    } else {
        return std::nullopt;
    }
}

bool mcl::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
