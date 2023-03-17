#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <iostream>

extern "C" {
    int cryptofuzz_aleo_privatetopublic(
            uint8_t* b_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_aleo_g1_add(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* b_x_bytes,
            uint8_t* b_y_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_aleo_g1_mul(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* b_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_aleo_g1_neg(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_aleo_g2_mul(
            uint8_t* a_v_bytes,
            uint8_t* a_w_bytes,
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* b_bytes,
            uint8_t* result_v,
            uint8_t* result_w,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_aleo_bignumcalc_fq(
            uint8_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* result);
    int cryptofuzz_aleo_bignumcalc_fr(
            uint8_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* result);
}
namespace cryptofuzz {
namespace module {

Aleo::Aleo(void) :
    Module("Aleo") { }

namespace aleo_detail {
    static component::G1 CorrectInfinityG1(const std::string& x, const std::string& y) {
        /* Aleo encodes infinity as (0, 1) */
        /* Correct for compatibility with other libraries */

        if ( x == "0" && y == "1") {
            return {"0", "0"};
        } else {
            return {x, y};
        }
    }

    static component::G2 CorrectInfinityG2(
            const std::string& v,
            const std::string& w,
            const std::string& x,
            const std::string& y) {
        /* Aleo encodes infinity as (1, 1, 0, 0) */
        /* Correct for compatibility with other libraries */

        if ( v == "0" && w == "1" && x == "0" && y == "0") {
            return {"0", "0", "0", "0"};
        } else {
            return {v, w, x, y};
        }
    }
}

std::optional<component::BLS_PublicKey> Aleo::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    std::optional<component::BLS_PublicKey> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> b_bytes;
    std::array<uint8_t, 48> result_x, result_y;

    CF_CHECK_NE(b_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_aleo_privatetopublic(
                    b_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    std::reverse(result_x.begin(), result_x.end());
    std::reverse(result_y.begin(), result_y.end());

    ret = aleo_detail::CorrectInfinityG1(
            util::BinToDec(result_x.data(), result_x.size()),
            util::BinToDec(result_y.data(), result_y.size()));

end:
    return ret;
}

std::optional<component::G1> Aleo::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_x_bytes, b_y_bytes;
    std::array<uint8_t, 48> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(b_x_bytes = util::DecToBin(op.b.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(b_y_bytes = util::DecToBin(op.b.second.ToTrimmedString(), 48), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_aleo_g1_add(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    b_x_bytes->data(),
                    b_y_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    std::reverse(result_x.begin(), result_x.end());
    std::reverse(result_y.begin(), result_y.end());

    ret = component::G1{
        util::BinToDec(result_x.data(), result_x.size()),
        util::BinToDec(result_y.data(), result_y.size()),
    };

end:
    return ret;
}

std::optional<component::G1> Aleo::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_bytes;
    std::array<uint8_t, 48> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(b_bytes = util::DecToBin(op.b.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_aleo_g1_mul(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    b_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    std::reverse(result_x.begin(), result_x.end());
    std::reverse(result_y.begin(), result_y.end());

    ret = aleo_detail::CorrectInfinityG1(
            util::BinToDec(result_x.data(), result_x.size()),
            util::BinToDec(result_y.data(), result_y.size()));

end:
    return ret;
}

std::optional<component::G1> Aleo::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes;
    std::array<uint8_t, 48> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 48), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_aleo_g1_neg(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    std::reverse(result_x.begin(), result_x.end());
    std::reverse(result_y.begin(), result_y.end());

    ret = component::G1{
        util::BinToDec(result_x.data(), result_x.size()),
        util::BinToDec(result_y.data(), result_y.size()),
    };

end:
    return ret;
}

std::optional<component::G2> Aleo::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("BLS12_377")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_v_bytes, a_w_bytes, a_x_bytes, a_y_bytes, b_bytes;
    std::array<uint8_t, 48> result_v, result_w, result_x, result_y;

    CF_CHECK_NE(a_v_bytes = util::DecToBin(op.a.first.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_w_bytes = util::DecToBin(op.a.first.second.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.second.first.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.second.ToTrimmedString(), 48), std::nullopt);
    CF_CHECK_NE(b_bytes = util::DecToBin(op.b.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_aleo_g2_mul(
                    a_v_bytes->data(),
                    a_w_bytes->data(),
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    b_bytes->data(),
                    result_v.data(),
                    result_w.data(),
                    result_x.data(),
                    result_y.data()), 0);

    std::reverse(result_v.begin(), result_v.end());
    std::reverse(result_w.begin(), result_w.end());
    std::reverse(result_x.begin(), result_x.end());
    std::reverse(result_y.begin(), result_y.end());

    ret = aleo_detail::CorrectInfinityG2(
            util::BinToDec(result_v.data(), result_v.size()),
            util::BinToDec(result_w.data(), result_w.size()),
            util::BinToDec(result_x.data(), result_x.size()),
            util::BinToDec(result_y.data(), result_y.size()));
end:
    return ret;
}

std::optional<component::Bignum> Aleo::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    size_t size = 0;
    if ( op.modulo->ToTrimmedString() == "8444461749428370424248824938781546531375899335154063827935233455917409239041" ) {
        size = 32;
    } else if ( op.modulo->ToTrimmedString() == "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177" ) {
        size = 48;
    } else {
        return std::nullopt;
    }
    std::optional<component::Bignum> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> bn0_bytes;
    std::optional<std::vector<uint8_t>> bn1_bytes;
    std::array<uint8_t, 32> result_fr;
    std::array<uint8_t, 48> result_fq;

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("Mul(A,B)"), 2 },
        { CF_CALCOP("InvMod(A,B)"), 3 },
        { CF_CALCOP("Sqr(A)"), 4 },
        { CF_CALCOP("Sqrt(A)"), 5 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    CF_CHECK_NE(bn0_bytes = util::DecToBin(op.bn0.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(bn1_bytes = util::DecToBin(op.bn1.ToTrimmedString(), size), std::nullopt);

    {
        if ( size == 32 ) {
            const auto res = cryptofuzz_aleo_bignumcalc_fr(
                    LUT.at(op.calcOp.Get()),
                    bn0_bytes->data(),
                    bn1_bytes->data(),
                    result_fr.data()
                    );

            CF_CHECK_NE(res, -1);
            std::reverse(result_fr.begin(), result_fr.end());
            ret = util::BinToDec(result_fr.data(), 32);
        } else if ( size == 48 ) {
            const auto res = cryptofuzz_aleo_bignumcalc_fq(
                    LUT.at(op.calcOp.Get()),
                    bn0_bytes->data(),
                    bn1_bytes->data(),
                    result_fq.data()
                    );

            CF_CHECK_NE(res, -1);
            std::reverse(result_fq.begin(), result_fq.end());
            ret = util::BinToDec(result_fq.data(), 48);
        } else {
            CF_UNREACHABLE();
        }
    }

end:
    return ret;
}

bool Aleo::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
