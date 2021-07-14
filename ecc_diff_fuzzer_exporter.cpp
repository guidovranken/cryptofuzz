#include <cryptofuzz/ecc_diff_fuzzer_exporter.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <stdio.h>
#include <fstream>
#if defined(CRYPTOFUZZ_EXPORT_ECC_DIFF_FUZZER)
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif

namespace cryptofuzz {

namespace ecc_diff_fuzzer_exporter {

std::optional<std::vector<uint8_t>> compressPoint(
        const std::string& ax,
        const std::string& ay,
        const uint16_t tlsId) {
#if !defined(CRYPTOFUZZ_EXPORT_ECC_DIFF_FUZZER)
    (void)ax;
    (void)ay;
    (void)tlsId;
    CF_ASSERT(0, "Cryptofuzz was compiled without support for ECC Diff Fuzzer exporter");
#else
    std::optional<std::vector<uint8_t>> ret = std::nullopt;

    static const int nid_list[28] = {
        NID_sect163k1, /* sect163k1 (1) */
        NID_sect163r1, /* sect163r1 (2) */
        NID_sect163r2, /* sect163r2 (3) */
        NID_sect193r1, /* sect193r1 (4) */
        NID_sect193r2, /* sect193r2 (5) */
        NID_sect233k1, /* sect233k1 (6) */
        NID_sect233r1, /* sect233r1 (7) */
        NID_sect239k1, /* sect239k1 (8) */
        NID_sect283k1, /* sect283k1 (9) */
        NID_sect283r1, /* sect283r1 (10) */
        NID_sect409k1, /* sect409k1 (11) */
        NID_sect409r1, /* sect409r1 (12) */
        NID_sect571k1, /* sect571k1 (13) */
        NID_sect571r1, /* sect571r1 (14) */
        NID_secp160k1, /* secp160k1 (15) */
        NID_secp160r1, /* secp160r1 (16) */
        NID_secp160r2, /* secp160r2 (17) */
        NID_secp192k1, /* secp192k1 (18) */
        NID_X9_62_prime192v1, /* secp192r1 (19) */
        NID_secp224k1, /* secp224k1 (20) */
        NID_secp224r1, /* secp224r1 (21) */
        NID_secp256k1, /* secp256k1 (22) */
        NID_X9_62_prime256v1, /* secp256r1 (23) */
        NID_secp384r1, /* secp384r1 (24) */
        NID_secp521r1, /* secp521r1 (25) */
        NID_brainpoolP256r1, /* brainpoolP256r1 (26) */
        NID_brainpoolP384r1, /* brainpoolP384r1 (27) */
        NID_brainpoolP512r1, /* brainpool512r1 (28) */
    };

    if (tlsId < 1 || tlsId > 28) {
        return ret;
    }

    const auto nid = nid_list[tlsId - 1];

    EC_GROUP* group = nullptr;
    EC_POINT* point = nullptr;
    BN_CTX* ctx = nullptr;
    BIGNUM *x = nullptr, *y = nullptr, *compressed = nullptr;
    unsigned char* point_bytes = nullptr;
    size_t point_size = 0;

    CF_CHECK_NE(group = EC_GROUP_new_by_curve_name(nid), nullptr);
    CF_CHECK_NE(point = EC_POINT_new(group), nullptr);
    CF_CHECK_NE(ctx = BN_CTX_new(), nullptr);
    CF_CHECK_NE(x = BN_new(), nullptr);
    CF_CHECK_NE(y = BN_new(), nullptr);
    CF_CHECK_NE(BN_dec2bn(&x, ax.c_str()), 0);
    CF_CHECK_NE(BN_dec2bn(&y, ay.c_str()), 0);
    CF_CHECK_NE(EC_POINT_set_affine_coordinates_GFp(group, point, x, y, nullptr), 0);
    CF_CHECK_NE(EC_POINT_is_on_curve(group, point, nullptr), 0);
    CF_CHECK_NE(compressed = BN_new(), nullptr);
    CF_CHECK_NE(EC_POINT_point2bn(group, point, POINT_CONVERSION_COMPRESSED, compressed, ctx), nullptr);
    point_size = BN_num_bytes(compressed);
    CF_CHECK_GT(point_size, 0);
    point_bytes = (unsigned char*)malloc(point_size);
    BN_bn2bin(compressed, point_bytes);

    ret = std::vector<uint8_t>(point_bytes + 1, point_bytes + point_size);

end:
    EC_GROUP_clear_free(group);
    EC_POINT_clear_free(point);
    BN_CTX_free(ctx);
    BN_clear_free(x);
    BN_clear_free(y);
    BN_clear_free(compressed);
    free(point_bytes);

    return ret;
#endif
}

std::optional<uint16_t> toTlsId(const uint64_t curveType) {
    switch ( curveType ) {
        case CF_ECC_CURVE("brainpool256r1"):
            return 26;
        case CF_ECC_CURVE("brainpool384r1"):
            return 27;
        case CF_ECC_CURVE("brainpool512r1"):
            return 28;
        case CF_ECC_CURVE("secp192k1"):
            return 18;
        case CF_ECC_CURVE("secp192r1"):
            return 19;
        case CF_ECC_CURVE("secp224k1"):
            return 20;
        case CF_ECC_CURVE("secp224r1"):
            return 21;
        case CF_ECC_CURVE("secp256k1"):
            return 22;
        case CF_ECC_CURVE("secp256r1"):
            return 23;
        case CF_ECC_CURVE("secp384r1"):
            return 24;
        case CF_ECC_CURVE("secp521r1"):
            return 25;
        default:
            return std::nullopt;
    }
}

static size_t bitlenFromTlsId(const uint16_t tlsId) {
    switch ( tlsId ) {
        case 18:
            //secp192k1
            return 192;
        case 19:
            //secp192r1
            return 192;
        case 20:
            //secp224k1
            return 224;
        case 21:
            //secp224r1
            return 224;
        case 22:
            //secp256k1
            return 256;
        case 23:
            //secp256r1
            return 256;
        case 24:
            //secp384r1
            return 384;
        case 25:
            //secp521r1
            return 521;
        case 26:
            //brainpoolP256r1
            return 256;
        case 27:
            //brainpoolP384r1
            return 384;
        case 28:
            //brainpoolP512r1
            return 512;
    }

    return 0;
}

static size_t ecdf_byteceil(const size_t numBits) {
    return ((numBits) + 7) >> 3;
}

} /* namespace ecc_diff_fuzzer_exporter */

ECC_Diff_Fuzzer_Exporter::ECC_Diff_Fuzzer_Exporter(const std::string filename, const std::string outDir) :
    filename(filename), outDir(outDir) {
}

void ECC_Diff_Fuzzer_Exporter::Run(void) {
    std::ifstream instream(filename, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    LoadInput(data);
}

void ECC_Diff_Fuzzer_Exporter::LoadInput(const std::vector<uint8_t> data) {
    try {
        Datasource ds(data.data(), data.size());
        const auto operation = ds.Get<uint64_t>();
        if ( operation != CF_OPERATION("ECC_Point_Add") && operation != CF_OPERATION("ECC_Point_Mul") ) {
            return;
        }
        const auto payload = ds.GetData(0, 1);
        const auto modifier = ds.GetData(0);
        Datasource ds2(payload.data(), payload.size());
        if ( operation == CF_OPERATION("ECC_Point_Add") ) {
            const auto op = operation::ECC_Point_Add(ds2, component::Modifier(modifier.data(), modifier.size()));

            const auto curveType = op.curveType.Get();

            const auto ax = op.a.first.ToTrimmedString();
            const auto ay = op.a.second.ToTrimmedString();

            const auto bx = op.b.first.ToTrimmedString();
            const auto by = op.b.second.ToTrimmedString();

            write_Add(curveType, ax, ay, bx, by);
        } else if ( operation == CF_OPERATION("ECC_Point_Mul") ) {
            const auto op = operation::ECC_Point_Mul(ds2, component::Modifier(modifier.data(), modifier.size()));

            const auto curveType = op.curveType.Get();

            const auto ax = op.a.first.ToTrimmedString();
            const auto ay = op.a.second.ToTrimmedString();

            const auto b = op.b.ToTrimmedString();

            write_Mul(curveType, ax, ay, b);
        }
    } catch ( ... ) { }
}

void ECC_Diff_Fuzzer_Exporter::write_Add(
        const uint64_t curveType,
        const std::string ax,
        const std::string ay,
        const std::string bx,
        const std::string by) {
    std::vector<uint8_t> out;

    const auto tlsId = ecc_diff_fuzzer_exporter::toTlsId(curveType);
    if ( tlsId == std::nullopt ) {
        return;
    }

    auto groupBitLen = ecc_diff_fuzzer_exporter::bitlenFromTlsId(*tlsId);

    if ( groupBitLen == 0 ) {
        return;
    }

    groupBitLen = ecc_diff_fuzzer_exporter::ecdf_byteceil(groupBitLen);

    out.push_back((*tlsId >> 8) & 0xFF);
    out.push_back(*tlsId & 0xFF);
    out.push_back(0x20);

    {
        const auto A = ecc_diff_fuzzer_exporter::compressPoint(ax, ay, *tlsId);
        if ( A == std::nullopt ) {
            return;
        }

        out.insert(std::end(out), std::begin(*A), std::end(*A));
    }

    {
        const auto B = ecc_diff_fuzzer_exporter::compressPoint(bx, by, *tlsId);
        if ( B == std::nullopt ) {
            return;
        }
        out.insert(std::end(out), std::begin(*B), std::end(*B));
    }

    write(out);
}

void ECC_Diff_Fuzzer_Exporter::write_Mul(
        const uint64_t curveType,
        const std::string ax,
        const std::string ay,
        const std::string b) {
    std::vector<uint8_t> out;

    const auto tlsId = ecc_diff_fuzzer_exporter::toTlsId(curveType);
    if ( tlsId == std::nullopt ) {
        return;
    }

    auto groupBitLen = ecc_diff_fuzzer_exporter::bitlenFromTlsId(*tlsId);

    if ( groupBitLen == 0 ) {
        return;
    }

    groupBitLen = ecc_diff_fuzzer_exporter::ecdf_byteceil(groupBitLen);

    out.push_back((*tlsId >> 8) & 0xFF);
    out.push_back(*tlsId & 0xFF);

    {
        const auto A = ecc_diff_fuzzer_exporter::compressPoint(ax, ay, *tlsId);
        if ( A == std::nullopt ) {
            return;
        }

        const auto B = util::DecToBin(b, A->size());

        if ( B == std::nullopt ) {
            return;
        }

        out.insert(std::end(out), std::begin(*B), std::end(*B));
        out.push_back(0x00);
        out.insert(std::end(out), std::begin(*A), std::end(*A));
    }

    write(out);
}

void ECC_Diff_Fuzzer_Exporter::write(const std::vector<uint8_t> data) {
    std::string filename = outDir + std::string("/") + util::SHA1(data);
    FILE* fp = fopen(filename.c_str(), "wb");
    fwrite(data.data(), data.size(), 1, fp);
    fclose(fp);
}


} /* namespace cryptofuzz */
