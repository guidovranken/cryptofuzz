#include "module.h"
#include <cryptofuzz/util.h>

extern "C" {
    int cryptofuzz_substrate_bn_g1_on_curve(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes);
    int cryptofuzz_substrate_bn_g1_add(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* b_x_bytes,
            uint8_t* b_y_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_substrate_bn_g1_mul(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* b_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
    int cryptofuzz_substrate_bn_g1_neg(
            uint8_t* a_x_bytes,
            uint8_t* a_y_bytes,
            uint8_t* result_x,
            uint8_t* result_y);
}

namespace cryptofuzz {
namespace module {

substrate_bn::substrate_bn(void) :
    Module("substrate-bn") { }

std::optional<bool> substrate_bn::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes;

    static const std::string prime = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    CF_CHECK_TRUE(op.g1.first.IsLessThan(prime));
    CF_CHECK_TRUE(op.g1.second.IsLessThan(prime));

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.g1.first.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.g1.second.ToTrimmedString(), 32), std::nullopt);

    ret = cryptofuzz_substrate_bn_g1_on_curve(
                    a_x_bytes->data(),
                    a_y_bytes->data()) == 0;

end:
    return ret;
}

std::optional<component::G1> substrate_bn::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_x_bytes, b_y_bytes;
    std::array<uint8_t, 32> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(b_x_bytes = util::DecToBin(op.b.first.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(b_y_bytes = util::DecToBin(op.b.second.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_substrate_bn_g1_add(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    b_x_bytes->data(),
                    b_y_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    ret = component::G1{
        util::BinToDec(result_x.data(), result_x.size()),
        util::BinToDec(result_y.data(), result_y.size()),
    };

end:
    return ret;
}

std::optional<component::G1> substrate_bn::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_bytes;
    std::array<uint8_t, 32> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(b_bytes = util::DecToBin(op.b.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_substrate_bn_g1_mul(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    b_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    ret = component::G1{
        util::BinToDec(result_x.data(), result_x.size()),
        util::BinToDec(result_y.data(), result_y.size()),
    };

end:
    return ret;
}

std::optional<component::G1> substrate_bn::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;

    if ( !op.curveType.Is(CF_ECC_CURVE("alt_bn128")) ) {
        return ret;
    }

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes;
    std::array<uint8_t, 32> result_x, result_y;

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);

    CF_CHECK_EQ(cryptofuzz_substrate_bn_g1_neg(
                    a_x_bytes->data(),
                    a_y_bytes->data(),
                    result_x.data(),
                    result_y.data()), 0);

    ret = component::G1{
        util::BinToDec(result_x.data(), result_x.size()),
        util::BinToDec(result_y.data(), result_y.size()),
    };

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
