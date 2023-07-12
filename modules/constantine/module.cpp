#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <boost/multiprecision/cpp_int.hpp>

extern "C" {
    #include <constantine_harness.h>
}
extern "C" {
    //#include "cryptofuzz.h"
}

namespace cryptofuzz {
namespace module {

Constantine::Constantine(void) :
    Module("Constantine") {
    NimMain();
}

namespace Constantine_detail {
    static std::vector<uint8_t> Pad(Datasource& ds, const std::vector<uint8_t> v) {
        return v;
    }
    template <size_t N = 32>
    static std::optional<std::array<uint8_t, N>> LoadField(const component::Bignum& bn) {
        (void)bn;
        std::optional<std::array<uint8_t, N>> ret = std::nullopt;
        std::array<uint8_t, N> r;

        std::optional<std::vector<uint8_t>> bytes;
        CF_CHECK_NE(bytes = util::DecToBin(bn.ToTrimmedString(), N), std::nullopt);
        memcpy(r.data(), bytes->data(), N);
        ret = r;
end:
        return ret;
    }
    template <size_t N = 32>
    static std::optional<std::array<uint8_t, N*2>> LoadG1(const component::G1& g1) {
        std::optional<std::array<uint8_t, N*2>> ret = std::nullopt;
        std::array<uint8_t, N*2> r;

        std::optional<std::array<uint8_t, N>> x_bytes, y_bytes;
        CF_CHECK_NE(x_bytes = LoadField<N>(g1.first.ToTrimmedString()), std::nullopt);
        CF_CHECK_NE(y_bytes = LoadField<N>(g1.second.ToTrimmedString()), std::nullopt);
        memcpy(r.data(), x_bytes->data(), N);
        memcpy(r.data() + N, y_bytes->data(), N);
        ret = r;
end:
        return ret;
    }

    template <size_t N = 32>
    static std::optional<std::array<uint8_t, N * 4>> LoadG2(const component::G2& g2) {
        std::optional<std::array<uint8_t, N * 4>> ret = std::nullopt;
        std::array<uint8_t, N * 4> r;

        std::optional<std::array<uint8_t, N>> v_bytes, w_bytes, x_bytes, y_bytes;
        CF_CHECK_NE(v_bytes = LoadField<N>(g2.first.first.ToTrimmedString()), std::nullopt);
        CF_CHECK_NE(w_bytes = LoadField<N>(g2.first.second.ToTrimmedString()), std::nullopt);
        CF_CHECK_NE(x_bytes = LoadField<N>(g2.second.first.ToTrimmedString()), std::nullopt);
        CF_CHECK_NE(y_bytes = LoadField<N>(g2.second.second.ToTrimmedString()), std::nullopt);
        memcpy(r.data(), v_bytes->data(), N);
        memcpy(r.data() + N, w_bytes->data(), N);
        memcpy(r.data() + (N * 2), x_bytes->data(), N);
        memcpy(r.data() + (N * 3), y_bytes->data(), N);
        ret = r;
end:
        return ret;
    }


    template <size_t N = 32>
    static component::G1 SaveG1(const std::array<uint8_t, N*2>& g1) {
        const auto p = g1.data();
        return component::G1{
            util::BinToDec(p, N),
            util::BinToDec(p + N, N),
        };
    }

    template <size_t N = 32>
    static component::G2 SaveG2(const std::array<uint8_t, N*4>& g2) {
        const auto p = g2.data();
        return component::G2{
            util::BinToDec(p , N),
            util::BinToDec(p + N, N),
            util::BinToDec(p + (N * 2), N),
            util::BinToDec(p + (N * 3), N),
        };
    }

    template <size_t N = 32>
    static component::Fp12 SaveFp12(const std::array<uint8_t, N * 12>& fp12) {
        const auto p = fp12.data();
        return component::Fp12{
            util::BinToDec(p + (0 * N), N),
            util::BinToDec(p + (1 * N), N),
            util::BinToDec(p + (2 * N), N),
            util::BinToDec(p + (3 * N), N),
            util::BinToDec(p + (4 * N), N),
            util::BinToDec(p + (5 * N), N),
#if 0
            std::string("0"),
            std::string("0"),
            std::string("0"),
            std::string("0"),
            std::string("0"),
            std::string("0"),
#else
            util::BinToDec(p + (6 * N), N),
            util::BinToDec(p + (7 * N), N),
            util::BinToDec(p + (8 * N), N),
            util::BinToDec(p + (9 * N), N),
            util::BinToDec(p + (10 * N), N),
            util::BinToDec(p + (11 * N), N),
#endif
        };
    }

    template <size_t N = 32>
    static std::optional<std::array<uint8_t, N * 12>> LoadFp12(const component::Fp12& fp12) {
        std::optional<std::array<uint8_t, N * 12>> ret = std::nullopt;
        std::array<uint8_t, N * 12> r;

        std::optional<std::array<uint8_t, N>> bytes;

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn1.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (0 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn2.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (1 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn3.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (2 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn4.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (3 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn5.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (4 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn6.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (5 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn7.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (6 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn8.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (7 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn9.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (8 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn10.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (9 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn11.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (10 * N), bytes->data(), bytes->size());

        CF_CHECK_NE(bytes = LoadField<N>(fp12.bn12.ToTrimmedString()), std::nullopt);
        memcpy(r.data() + (11 * N), bytes->data(), bytes->size());

        ret = r;
end:
        return ret;
    }

    template <size_t N>
    static component::Bignum SaveField(const std::array<uint8_t, N>& field) {
        return util::BinToDec(field.data(), N);
    }
}

std::optional<bool> Constantine::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> g1_bytes;
        CF_CHECK_NE(g1_bytes = Constantine_detail::LoadG1(op.g1), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_isg1oncurve(0, g1_bytes->data(), 64);
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> g1_bytes;
        CF_CHECK_NE(g1_bytes = Constantine_detail::LoadG1<48>(op.g1), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_isg1oncurve(1, g1_bytes->data(), 96);
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> a_bytes, b_bytes;
        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG1(op.b), std::nullopt);
        std::array<uint8_t, 64> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_add(
                    0,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()), 0);
        ret = Constantine_detail::SaveG1(result);

    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> a_bytes, b_bytes;
        std::array<uint8_t, 96> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG1<48>(op.b), std::nullopt);
        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_add(
                    1,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> a_bytes;
        std::optional<std::array<uint8_t, 32>> b_bytes;
        std::array<uint8_t, 64> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadField(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_mul(
                    0,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> a_bytes;
        std::optional<std::array<uint8_t, 48>> b_bytes;
        std::array<uint8_t, 96> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadField<48>(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_mul(
                    1,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::G1> ret = std::nullopt;

    std::vector<uint8_t> points, scalars;

    const size_t num = op.points_scalars.points_scalars.size();

    uint8_t which = 0;

    try {
        which = ds.Get<uint8_t>() % 4;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    CF_CHECK_NE(num, 0);

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        for (size_t i = 0; i < num; i++) {
            std::optional<std::array<uint8_t, 64>> a_bytes;
            std::optional<std::array<uint8_t, 32>> b_bytes;

            const auto& cur = op.points_scalars.points_scalars[i];

            CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<32>(cur.first), std::nullopt);
            points.insert(points.end(), a_bytes->begin(), a_bytes->end());

            CF_CHECK_NE(b_bytes = Constantine_detail::LoadField<32>(cur.second), std::nullopt);
            scalars.insert(scalars.end(), b_bytes->begin(), b_bytes->end());
        }

        std::array<uint8_t, 64> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_multiexp(
                    0,
                    points.data(), points.size(),
                    scalars.data(), scalars.size(),
                    num,
                    which,
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<32>(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        for (size_t i = 0; i < num; i++) {
            std::optional<std::array<uint8_t, 96>> a_bytes;
            std::optional<std::array<uint8_t, 32>> b_bytes;

            const auto& cur = op.points_scalars.points_scalars[i];

            CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<48>(cur.first), std::nullopt);
            points.insert(points.end(), a_bytes->begin(), a_bytes->end());

            CF_CHECK_NE(b_bytes = Constantine_detail::LoadField<32>(cur.second), std::nullopt);
            scalars.insert(scalars.end(), b_bytes->begin(), b_bytes->end());
        }

        std::array<uint8_t, 96> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_multiexp(
                    1,
                    points.data(), points.size(),
                    scalars.data(), scalars.size(),
                    num,
                    which,
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

    if ( which == 1 ) return std::nullopt;
end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> a_bytes;
        std::array<uint8_t, 64> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1(op.a), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_neg(
                    0,
                    a_bytes->data(), a_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> a_bytes;
        std::array<uint8_t, 96> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<48>(op.a), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g1_neg(
                    1,
                    a_bytes->data(), a_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

std::optional<bool> Constantine::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> a_bytes, b_bytes;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG1(op.b), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_g1_iseq(
                    0,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size());

        CF_CHECK_NE(r, -1);
        ret = r == 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> a_bytes, b_bytes;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG1<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG1<48>(op.b), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_g1_iseq(
                    1,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size());

        CF_CHECK_NE(r, -1);
        ret = r == 1;
    }

end:
    return ret;
}

std::optional<bool> Constantine::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 128>> g2_bytes;

        /* XXX */
        if ( op.g2.first.first.ToTrimmedString() == "0" &&
                op.g2.first.second.ToTrimmedString() == "1" &&
                op.g2.second.first.ToTrimmedString() == "0" &&
                op.g2.second.second.ToTrimmedString() == "0" ) {
            return ret;
        }

        CF_CHECK_NE(g2_bytes = Constantine_detail::LoadG2(op.g2), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_isg2oncurve(0, g2_bytes->data(), 32 * 4);
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> g2_bytes;

        CF_CHECK_NE(g2_bytes = Constantine_detail::LoadG2<48>(op.g2), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_isg2oncurve(1, g2_bytes->data(), 48 * 4);
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    }

end:
    return ret;
}

std::optional<component::G2> Constantine::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 128>> a_bytes, b_bytes;
        std::array<uint8_t, 128> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG2(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_add(
                    0,
                    a_bytes->data(), 128,
                    b_bytes->data(), 128,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> a_bytes, b_bytes;
        std::array<uint8_t, 48 * 4> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG2<48>(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_add(
                    1,
                    a_bytes->data(), 48 * 4,
                    b_bytes->data(), 48 * 4,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2<48>(result);
    }

end:
    return ret;
}

std::optional<component::G2> Constantine::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 128>> a_bytes;
        std::optional<std::array<uint8_t, 32>> b_bytes;
        std::array<uint8_t, 128> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadField(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_mul(
                    0,
                    a_bytes->data(), 128,
                    b_bytes->data(), 32,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> a_bytes;
        std::optional<std::array<uint8_t, 32>> b_bytes;
        std::array<uint8_t, 48 * 4> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadField(op.b), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_mul(
                    1,
                    a_bytes->data(), 48 * 4,
                    b_bytes->data(), 32,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2<48>(result);
    }

end:
    return ret;
}

std::optional<component::G2> Constantine::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 128>> a_bytes;
        std::array<uint8_t, 128> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2(op.a), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_neg(
                    0,
                    a_bytes->data(), 128,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> a_bytes;
        std::array<uint8_t, 48 * 4> result;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2<48>(op.a), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_g2_neg(
                    1,
                    a_bytes->data(), 48 * 4,
                    result.data()), 0);

        ret = Constantine_detail::SaveG2<48>(result);
    }

end:
    return ret;
}

std::optional<bool> Constantine::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 128>> a_bytes, b_bytes;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG2(op.b), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_g2_iseq(
                    0,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size());

        CF_CHECK_NE(r, -1);
        ret = r == 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> a_bytes, b_bytes;

        CF_CHECK_NE(a_bytes = Constantine_detail::LoadG2<48>(op.a), std::nullopt);
        CF_CHECK_NE(b_bytes = Constantine_detail::LoadG2<48>(op.b), std::nullopt);

        const auto r = cryptofuzz_constantine_bls_g2_iseq(
                    1,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size());

        CF_CHECK_NE(r, -1);
        ret = r == 1;
    }

end:
    return ret;
}

std::optional<component::Fp12> Constantine::OpBLS_Pairing(operation::BLS_Pairing& op) {
    std::optional<component::Fp12> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 64>> g1_bytes;
        std::optional<std::array<uint8_t, 128>> g2_bytes;
        std::array<uint8_t, 32 * 12> result;

        CF_CHECK_NE(g1_bytes = Constantine_detail::LoadG1(op.g1), std::nullopt);
        CF_CHECK_NE(g2_bytes = Constantine_detail::LoadG2(op.g2), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_pairing(
                    0,
                    g1_bytes->data(), g1_bytes->size(),
                    g2_bytes->data(), g2_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveFp12(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 2>> g1_bytes;
        std::optional<std::array<uint8_t, 48 * 4>> g2_bytes;
        std::array<uint8_t, 48 * 12> result;

        CF_CHECK_NE(g1_bytes = Constantine_detail::LoadG1<48>(op.g1), std::nullopt);
        CF_CHECK_NE(g2_bytes = Constantine_detail::LoadG2<48>(op.g2), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_pairing(
                    1,
                    g1_bytes->data(), g1_bytes->size(),
                    g2_bytes->data(), g2_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveFp12<48>(result);
    }

end:
    return ret;
}

std::optional<component::Fp12> Constantine::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    std::optional<component::Fp12> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::optional<std::array<uint8_t, 32 * 12>> fp12_bytes;

        CF_CHECK_NE(fp12_bytes = Constantine_detail::LoadFp12(op.fp12), std::nullopt);
        std::array<uint8_t, 32 * 12> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_finalexp(
                    0,
                    fp12_bytes->data(), fp12_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveFp12(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 12>> fp12_bytes;

        CF_CHECK_NE(fp12_bytes = Constantine_detail::LoadFp12<48>(op.fp12), std::nullopt);
        std::array<uint8_t, 48 * 12> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_finalexp(
                    1,
                    fp12_bytes->data(), fp12_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveFp12<48>(result);
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    std::optional<component::G1> ret = std::nullopt;

    auto aug = op.aug.Get();
    auto msg = op.cleartext.Get();
    auto dst = op.dest.Get();

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::array<uint8_t, 64> result;
        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_hashtog1(
                    0,
                    aug.data(), aug.size(),
                    msg.data(), msg.size(),
                    dst.data(), dst.size(),
                    result.data()), 0);
        ret = Constantine_detail::SaveG1(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::array<uint8_t, 96> result;
        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_hashtog1(
                    1,
                    aug.data(), aug.size(),
                    msg.data(), msg.size(),
                    dst.data(), dst.size(),
                    result.data()), 0);
        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

std::optional<component::G2> Constantine::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    std::optional<component::G2> ret = std::nullopt;

    auto aug = op.aug.Get();
    auto msg = op.cleartext.Get();
    auto dst = op.dest.Get();

    if ( op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        std::array<uint8_t, 128> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_hashtog2(
                    0,
                    aug.data(), aug.size(),
                    msg.data(), msg.size(),
                    dst.data(), dst.size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG2(result);
    } else if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::array<uint8_t, 48 * 4> result;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_hashtog2(
                    1,
                    aug.data(), aug.size(),
                    msg.data(), msg.size(),
                    dst.data(), dst.size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG2<48>(result);
    }

end:
    return ret;
}

std::optional<component::BLS_KeyPair> Constantine::OpBLS_GenerateKeyPair(operation::BLS_GenerateKeyPair& op) {
    std::optional<component::BLS_KeyPair> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::array<uint8_t, 32> result_priv;
        std::array<uint8_t, 48 * 2> result_pub;
        CF_CHECK_EQ(op.info.GetSize(), 0);

        auto ikm = op.ikm.Get();

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_generatekeypair(
                    ikm.data(),
                    ikm.size(),
                    result_priv.data(),
                    result_pub.data()), 0);
        ret = {
            Constantine_detail::SaveField(result_priv),
            Constantine_detail::SaveG1<48>(result_pub)};
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48>> compressed;
        std::array<uint8_t, 48 * 2> result;

        CF_CHECK_NE(compressed = Constantine_detail::LoadField<48>(op.compressed), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_decompress_g1(
                    compressed->data(), compressed->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

std::optional<component::Bignum> Constantine::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 96>> g1_bytes;
        std::array<uint8_t, 48> result;

        CF_CHECK_NE(g1_bytes = Constantine_detail::LoadG1<48>(op.uncompressed), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_compress_g1(
                    g1_bytes->data(), g1_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveField<48>(result);
    }

end:
    return ret;
}

std::optional<component::G2> Constantine::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48>> a, b;
        std::array<uint8_t, 48 * 4> result;
        std::vector<uint8_t> compressed;

        CF_CHECK_NE(a = Constantine_detail::LoadField<48>(op.compressed.first), std::nullopt);
        CF_CHECK_NE(b = Constantine_detail::LoadField<48>(op.compressed.second), std::nullopt);

        compressed.insert(compressed.end(), a->begin(), a->end());
        compressed.insert(compressed.end(), b->begin(), b->end());

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_decompress_g2(
                    compressed.data(), compressed.size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG2<48>(result);
    }

end:
    return ret;
}

std::optional<component::G1> Constantine::OpBLS_Compress_G2(operation::BLS_Compress_G2& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( op.curveType.Is(CF_ECC_CURVE("BLS12_381")) ) {
        std::optional<std::array<uint8_t, 48 * 4>> g2_bytes;
        std::array<uint8_t, 96> result;

        CF_CHECK_NE(g2_bytes = Constantine_detail::LoadG2<48>(op.uncompressed), std::nullopt);

        CF_CHECK_EQ(
                cryptofuzz_constantine_bls_compress_g2(
                    g2_bytes->data(), g2_bytes->size(),
                    result.data()), 0);

        ret = Constantine_detail::SaveG1<48>(result);
    }

end:
    return ret;
}

namespace Constantine_detail {
    std::optional<component::Bignum> OpBignumCalc_Mod(operation::BignumCalc& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::Bignum> ret = std::nullopt;
        bool alt = false;

        uint8_t calcop;
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                calcop = 0;
                break;
            case    CF_CALCOP("Sub(A,B)"):
                calcop = 1;
                break;
            case    CF_CALCOP("Mul(A,B)"):
                calcop = 2;
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                calcop = 3;
                break;
            case    CF_CALCOP("Sqr(A)"):
                calcop = 4;
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                calcop = 5;
                break;
            case    CF_CALCOP("Sqrt(A)"):
                calcop = 6;
                break;
            case    CF_CALCOP("Not(A)"):
                calcop = 7;
                break;
            case    CF_CALCOP("IsOne(A)"):
                calcop = 8;
                break;
            case    CF_CALCOP("IsZero(A)"):
                calcop = 9;
                break;
            case    CF_CALCOP("Exp(A,B)"):
                calcop = 10;
                break;
            default:
                return ret;
        }

        try {
            alt = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
            std::optional<std::array<uint8_t, 32>> bn0_bytes, bn1_bytes;
            std::array<uint8_t, 32> result;
            CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadField<32>(op.bn0), std::nullopt);
            CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadField<32>(op.bn1), std::nullopt);
            CF_CHECK_EQ(
                    cryptofuzz_constantine_bignumcalc_fr(
                        0,
                        calcop,
                        bn0_bytes->data(), 32,
                        bn1_bytes->data(), 32,
                        alt,
                        result.data()), 0);
            ret = Constantine_detail::SaveField(result);
        } else if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
            std::optional<std::array<uint8_t, 32>> bn0_bytes, bn1_bytes;
            std::array<uint8_t, 32> result;
            CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadField<32>(op.bn0), std::nullopt);
            CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadField<32>(op.bn1), std::nullopt);
            CF_CHECK_EQ(
                    cryptofuzz_constantine_bignumcalc_fp(
                        0,
                        calcop,
                        bn0_bytes->data(), 32,
                        bn1_bytes->data(), 32,
                        alt,
                        result.data()), 0);
            ret = Constantine_detail::SaveField(result);
        } else if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
            std::optional<std::array<uint8_t, 32>> bn0_bytes, bn1_bytes;
            std::array<uint8_t, 32> result;
            CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadField<32>(op.bn0), std::nullopt);
            CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadField<32>(op.bn1), std::nullopt);
            CF_CHECK_EQ(
                    cryptofuzz_constantine_bignumcalc_fr(
                        1,
                        calcop,
                        bn0_bytes->data(), 32,
                        bn1_bytes->data(), 32,
                        alt,
                        result.data()), 0);
            ret = Constantine_detail::SaveField(result);
        } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
            std::optional<std::array<uint8_t, 48>> bn0_bytes, bn1_bytes;
            std::array<uint8_t, 48> result;
            CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadField<48>(op.bn0), std::nullopt);
            CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadField<48>(op.bn1), std::nullopt);
            CF_CHECK_EQ(
                    cryptofuzz_constantine_bignumcalc_fp(
                        1,
                        calcop,
                        bn0_bytes->data(), 48,
                        bn1_bytes->data(), 48,
                        alt,
                        result.data()), 0);
            ret = Constantine_detail::SaveField(result);
        }

end:
        return ret;
    }
}

std::optional<component::Fp2> Constantine::OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Fp2> ret = std::nullopt;

    uint8_t calcop;
    bool alt = false;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            calcop = 0;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            calcop = 1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            calcop = 2;
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            calcop = 3;
            break;
        case    CF_CALCOP("Sqr(A)"):
            calcop = 4;
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            calcop = 5;
            break;
        case    CF_CALCOP("Sqrt(A)"):
            calcop = 6;
            break;
        case    CF_CALCOP("Not(A)"):
            calcop = 7;
            break;
        case    CF_CALCOP("IsOne(A)"):
            calcop = 8;
            break;
        case    CF_CALCOP("IsZero(A)"):
            calcop = 9;
            break;
        case    CF_CALCOP("Exp(A,B)"):
            calcop = 10;
            break;
        default:
            return ret;
    }

    try {
        alt = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if 0
    std::optional<std::array<uint8_t, 32 * 2>> bn0_bytes, bn1_bytes;
    std::array<uint8_t, 32 * 2> result;

    CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadG1(op.bn0), std::nullopt);
    CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadG1(op.bn1), std::nullopt);

    CF_CHECK_EQ(
            cryptofuzz_constantine_bignumcalc_fp2(
                0,
                calcop,
                bn0_bytes->data(), bn0_bytes->size(),
                bn1_bytes->data(), bn1_bytes->size(),
                alt,
                result.data()), 0);

    ret = Constantine_detail::SaveG1(result);
#else
    std::optional<std::array<uint8_t, 48 * 2>> bn0_bytes, bn1_bytes;
    std::array<uint8_t, 48 * 2> result;

    CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadG1<48>(op.bn0), std::nullopt);
    CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadG1<48>(op.bn1), std::nullopt);

    CF_CHECK_EQ(
            cryptofuzz_constantine_bignumcalc_fp2(
                1,
                calcop,
                bn0_bytes->data(), bn0_bytes->size(),
                bn1_bytes->data(), bn1_bytes->size(),
                alt,
                result.data()), 0);

    ret = Constantine_detail::SaveG1<48>(result);
#endif

end:
    return ret;
}

std::optional<component::Fp12> Constantine::OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Fp12> ret = std::nullopt;

    uint8_t calcop;
    bool alt = false;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            calcop = 0;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            calcop = 1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            calcop = 2;
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            calcop = 3;
            break;
        case    CF_CALCOP("Sqr(A)"):
            calcop = 4;
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            calcop = 5;
            break;
        case    CF_CALCOP("Sqrt(A)"):
            calcop = 6;
            break;
        case    CF_CALCOP("Not(A)"):
            calcop = 7;
            break;
        case    CF_CALCOP("IsOne(A)"):
            calcop = 8;
            break;
        case    CF_CALCOP("IsZero(A)"):
            calcop = 9;
            break;
        case    CF_CALCOP("Exp(A,B)"):
            calcop = 10;
            break;
        default:
            return ret;
    }

    try {
        alt = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if 0
    std::optional<std::array<uint8_t, 32 * 12>> bn0_bytes, bn1_bytes;
    std::array<uint8_t, 32 * 12> result;

    CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadFp12(op.bn0), std::nullopt);
    CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadFp12(op.bn1), std::nullopt);

    CF_CHECK_EQ(
            cryptofuzz_constantine_bignumcalc_fp12(
                0,
                calcop,
                bn0_bytes->data(), bn0_bytes->size(),
                bn1_bytes->data(), bn1_bytes->size(),
                alt,
                result.data()), 0);

    ret = Constantine_detail::SaveFp12(result);
#else
    std::optional<std::array<uint8_t, 48 * 12>> bn0_bytes, bn1_bytes;
    std::array<uint8_t, 48 * 12> result;

    CF_CHECK_NE(bn0_bytes = Constantine_detail::LoadFp12<48>(op.bn0), std::nullopt);
    CF_CHECK_NE(bn1_bytes = Constantine_detail::LoadFp12<48>(op.bn1), std::nullopt);

    CF_CHECK_EQ(
            cryptofuzz_constantine_bignumcalc_fp12(
                1,
                calcop,
                bn0_bytes->data(), bn0_bytes->size(),
                bn1_bytes->data(), bn1_bytes->size(),
                alt,
                result.data()), 0);

    ret = Constantine_detail::SaveFp12<48>(result);
#endif

end:
    return ret;
}

bool Constantine::SupportsModularBignumCalc(void) const {
    return true;
}

std::optional<component::Bignum> Constantine::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo != std::nullopt ) {
        return Constantine_detail::OpBignumCalc_Mod(op);
    }

    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        /* Don't run with even modulus.
         *
         * https://github.com/guidovranken/nimbus-audit/issues/5
         */
        const auto s = op.bn2.ToTrimmedString();
        if ( (s[s.size()-1] - '0') % 2 == 0 ) {
            return ret;
        }

        std::vector<uint8_t> result;
        std::vector<uint8_t> input;
        uint64_t gas = 0, loops = 0;

        const auto b = Constantine_detail::Pad(ds, *op.bn0.ToBin());
        const auto bl = util::DecToBin(std::to_string(b.size()), 32);
        const auto e = Constantine_detail::Pad(ds, *op.bn1.ToBin());
        const auto el = util::DecToBin(std::to_string(e.size()), 32);
        const auto m = Constantine_detail::Pad(ds, *op.bn2.ToBin());
        const auto ml = util::DecToBin(std::to_string(m.size()), 32);
        input.insert(input.end(), bl->begin(), bl->end());
        input.insert(input.end(), el->begin(), el->end());
        input.insert(input.end(), ml->begin(), ml->end());
        input.insert(input.end(), b.begin(), b.end());
        input.insert(input.end(), e.begin(), e.end());
        input.insert(input.end(), m.begin(), m.end());

        result.resize(m.size());
        memset(result.data(), 0, result.size());

        //gas = static_cast<uint64_t>(
        //        Geth_ModExp_RequiredGas(Constantine_detail::toGoSlice(input)));

        /* Enable to test for slow repeated modexp calls */
        //loops = 30000000 / gas;

        CF_CHECK_EQ(
                cryptofuzz_constantine_bignumcalc_modexp(
                    loops,
                    input.data(), input.size(),
                    m.size(),
                    result.data()), 1);

        ret = util::BinToDec(result.data(), result.size());
    } else {
        uint8_t calcop;
        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                calcop = 0;
                break;
            case    CF_CALCOP("Sub(A,B)"):
                calcop = 1;
                break;
            case    CF_CALCOP("Mul(A,B)"):
                calcop = 2;
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                calcop = 3;
                break;
            case    CF_CALCOP("Sqr(A)"):
                calcop = 4;
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                calcop = 5;
                break;
            case    CF_CALCOP("IsGt(A,B)"):
                calcop = 6;
                break;
            case    CF_CALCOP("IsGte(A,B)"):
                calcop = 7;
                break;
            case    CF_CALCOP("IsLt(A,B)"):
                calcop = 8;
                break;
            case    CF_CALCOP("IsLte(A,B)"):
                calcop = 9;
                break;
            case    CF_CALCOP("IsZero(A)"):
                calcop = 10;
                break;
            case    CF_CALCOP("IsOne(A)"):
                calcop = 11;
                break;
            case    CF_CALCOP("IsOdd(A)"):
                calcop = 12;
                break;
            case    CF_CALCOP("IsEven(A)"):
                calcop = 13;
                break;
            case    CF_CALCOP("Zero()"):
                calcop = 14;
                break;
            case    CF_CALCOP("One()"):
                calcop = 15;
                break;
            case    CF_CALCOP("LSB(A)"):
                calcop = 16;
                break;
            default:
                return ret;
        }

        auto a_bytes = util::DecToBin(op.bn0.ToTrimmedString(), 4096);
        if ( a_bytes == std::nullopt ) {
            return ret;
        }
        auto b_bytes = util::DecToBin(op.bn1.ToTrimmedString(), 4096);
        if ( b_bytes == std::nullopt ) {
            return ret;
        }
        auto c_bytes = util::DecToBin(op.bn2.ToTrimmedString(), 4096);
        if ( c_bytes == std::nullopt ) {
            return ret;
        }

        std::array<uint8_t, 4096> result;
        memset(result.data(), 0, result.size());

        bool alt = false;

        try {
            alt = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        CF_CHECK_EQ(
                cryptofuzz_constantine_bignumcalc(
                    calcop,
                    a_bytes->data(), a_bytes->size(),
                    b_bytes->data(), b_bytes->size(),
                    c_bytes->data(), c_bytes->size(),
                    alt ? 1 : 0,
                    result.data()), 1);

        if ( op.calcOp.Is(CF_CALCOP("InvMod(A,B)")) ) {
            /* The result of Constantine's invmod and invmod_vartime
             * is undefined is the inverse doesn't exist.
             *
             * Check if the return value is in fact the inverse, return 0
             * otherwise.
             */
            const boost::multiprecision::cpp_int A(op.bn0.ToTrimmedString());
            const boost::multiprecision::cpp_int B(op.bn1.ToTrimmedString());
            const boost::multiprecision::cpp_int Inv(util::BinToDec(result.data(), result.size()));
            const boost::multiprecision::cpp_int R = (A * Inv) % B;

            if ( R == 1 ) {
                ret = util::BinToDec(result.data(), result.size());
            } else {
                ret = component::Bignum{std::string("0")};
            }
        } else {
            ret = util::BinToDec(result.data(), result.size());
        }
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
