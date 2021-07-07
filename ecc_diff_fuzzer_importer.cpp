#include <cryptofuzz/ecc_diff_fuzzer_importer.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <stdio.h>
#include <fstream>
#if defined(CRYPTOFUZZ_IMPORT_ECC_DIFF_FUZZER)
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif

namespace cryptofuzz {

namespace ecc_diff_fuzzer_importer {

using Point = std::optional<std::pair<std::string, std::string>>;

Point decompressPoint(
        const std::vector<uint8_t> data,
        const bool compressed,
        const uint16_t tlsId) {
#if !defined(CRYPTOFUZZ_IMPORT_ECC_DIFF_FUZZER)
    (void)data;
    (void)compressed;
    (void)tlsId;
    CF_ASSERT(0, "Cryptofuzz was compiled without support for ECC Diff Fuzzer importer");
#else
    Point ret = std::nullopt;

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
    BIGNUM* in = nullptr, *x = nullptr, *y = nullptr;;
    char* x_str = nullptr, *y_str = nullptr;

    CF_CHECK_NE(group = EC_GROUP_new_by_curve_name(nid), nullptr);
    CF_CHECK_NE(point = EC_POINT_new(group), nullptr);
    CF_CHECK_NE(in = BN_bin2bn(data.data(), data.size(), nullptr), nullptr);
    CF_CHECK_NE(EC_POINT_set_compressed_coordinates_GFp(group, point, in, compressed ? 1 : 0, nullptr), 0);
    CF_CHECK_NE(EC_POINT_is_on_curve(group, point, nullptr), 0);
    CF_CHECK_NE(x = BN_new(), nullptr);
    CF_CHECK_NE(y = BN_new(), nullptr);
    CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr), 0);
    CF_CHECK_NE(x_str = BN_bn2dec(x), nullptr);
    CF_CHECK_NE(y_str = BN_bn2dec(y), nullptr);

    ret = {std::string(x_str), std::string(y_str)};
end:
    EC_GROUP_clear_free(group);
    EC_POINT_clear_free(point);
    BN_clear_free(in);
    BN_clear_free(x);
    BN_clear_free(y);
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    return ret;
#endif
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

} /* namespace ecc_diff_fuzzer_importer */

ECC_Diff_Fuzzer_Importer::ECC_Diff_Fuzzer_Importer(const std::string filename, const std::string outDir) :
    filename(filename), outDir(outDir) {
}

void ECC_Diff_Fuzzer_Importer::Run(void) {
    std::ifstream instream(filename, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    LoadInput(data);
}

void ECC_Diff_Fuzzer_Importer::LoadInput(const std::vector<uint8_t> data) {
    ecc_diff_fuzzer_importer::Point A, B;
    std::string multiplier;

    size_t left = data.size();

    if ( left < 5 ) {
        return;
    }

    const uint16_t tlsId = ((size_t)data[0] << 8) | data[1];
    left -= 2;

    auto groupBitLen = ecc_diff_fuzzer_importer::bitlenFromTlsId(tlsId);

    if ( groupBitLen == 0 ) {
        return;
    }

    groupBitLen = ecc_diff_fuzzer_importer::ecdf_byteceil(groupBitLen);

    if (left < 1 + 2 * groupBitLen) {
        return;
    }

    if (left > 1 + 2 * groupBitLen) {
        left = groupBitLen;
    }

    const auto bignumSize = left / 2;
    const bool isAdd = data[bignumSize + 2] & 0x80;

    if ( isAdd ) {
        A = ecc_diff_fuzzer_importer::decompressPoint(
                    std::vector<uint8_t>(
                        data.data() + 3,
                        data.data() + 3 + (left - bignumSize - 1)),
                    data[bignumSize + 2] & 0x2,
                    tlsId);
        if ( A == std::nullopt ) {
            return;
        }
    }

    B = ecc_diff_fuzzer_importer::decompressPoint(
            std::vector<uint8_t>(
                data.data() + 3 + bignumSize,
                data.data() + 3 + bignumSize + (left - bignumSize - 1)),
            data[bignumSize + bignumSize + 2] & 0x2,
            tlsId);
    if ( B == std::nullopt ) {
        return;
    }

    if ( !isAdd ) {
        multiplier = cryptofuzz::util::BinToDec(data.data() + 2, bignumSize);
    }

    nlohmann::json parameters;
    parameters["modifier"] = "";

    switch ( tlsId ) {
        case 18:
            parameters["curveType"] = CF_ECC_CURVE("secp192k1");
            break;
        case 19:
            parameters["curveType"] = CF_ECC_CURVE("secp192r1");
            break;
        case 20:
            parameters["curveType"] = CF_ECC_CURVE("secp224k1");
            break;
        case 21:
            parameters["curveType"] = CF_ECC_CURVE("secp224r1");
            break;
        case 22:
            parameters["curveType"] = CF_ECC_CURVE("secp256k1");
            break;
        case 23:
            parameters["curveType"] = CF_ECC_CURVE("secp256r1");
            break;
        case 24:
            parameters["curveType"] = CF_ECC_CURVE("secp384r1");
            break;
        case 25:
            parameters["curveType"] = CF_ECC_CURVE("secp521r1");
            break;
        case 26:
            parameters["curveType"] = CF_ECC_CURVE("brainpool256r1");
            break;
        case 27:
            parameters["curveType"] = CF_ECC_CURVE("brainpool384r1");
            break;
        case 28:
            parameters["curveType"] = CF_ECC_CURVE("brainpool512r1");
            break;
        default:
            CF_UNREACHABLE();
    }

    if ( isAdd ) {
        parameters["a_x"] = A->first;
        parameters["a_y"] = A->second;
        parameters["b_x"] = B->first;
        parameters["b_y"] = B->second;
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        cryptofuzz::operation::ECC_Point_Add op(parameters);
        op.Serialize(dsOut2);

        write(CF_OPERATION("ECC_Point_Add"), dsOut2);
    } else {
        parameters["a_x"] = B->first;
        parameters["a_y"] = B->second;
        parameters["b"] = multiplier;
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        cryptofuzz::operation::ECC_Point_Mul op(parameters);
        op.Serialize(dsOut2);

        write(CF_OPERATION("ECC_Point_Mul"), dsOut2);
    }
}

void ECC_Diff_Fuzzer_Importer::write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2) {
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    /* Operation ID */
    dsOut.Put<uint64_t>(operation);

    dsOut.PutData(dsOut2.GetOut());

    /* Modifier */
    dsOut.PutData(std::vector<uint8_t>(0));

    /* Module ID */
    dsOut.Put<uint64_t>(CF_MODULE("OpenSSL"));

    /* Terminator */
    dsOut.Put<bool>(false);

    {
        std::string filename = outDir + std::string("/") + util::SHA1(dsOut.GetOut());
        FILE* fp = fopen(filename.c_str(), "wb");
        fwrite(dsOut.GetOut().data(), dsOut.GetOut().size(), 1, fp);
        fclose(fp);
    }
}

} /* namespace cryptofuzz */
