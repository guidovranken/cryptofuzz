#include <cryptofuzz/openssl_importer.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <stdio.h>
#include <fstream>
#include "config.h"

namespace cryptofuzz {

OpenSSL_Importer::OpenSSL_Importer(const std::string filename, const std::string outDir, const enum type t) :
    filename(filename), outDir(outDir), t(t) {
}

void OpenSSL_Importer::Run(void) {
    std::ifstream instream(filename, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    LoadInput(data);
}

void OpenSSL_Importer::LoadInput(const std::vector<uint8_t> data) {

    nlohmann::json parameters;
    parameters["modifier"] = "";
    parameters["bn4"] = "";

    if ( t == ExpMod ) {
        if ( data.size() < 3 ) {
            return;
        }

        const uint8_t* ptr = data.data();
        const size_t size = data.size() - 3;
        const size_t l1 = (ptr[0] * size) / 255;
        ptr++;
        const size_t l2 = (ptr[0] * (size - l1)) / 255;
        ptr++;
        const size_t l3 = size - l1 - l2;
        const bool bn1_neg = ptr[0] & 1;
        const bool bn3_neg = ptr[0] & 4;
        ptr++;

        auto bn1 = util::BinToDec(ptr, l1);
        if ( bn1_neg ) {
            bn1 = "-" + bn1;
        }
        const auto bn2 = util::BinToDec(ptr + l1, l2);
        auto bn3 = util::BinToDec(ptr + l1 + l2, l3);
        if ( bn3_neg ) {
            bn3 = "-" + bn3;
        }

        if ( bn1.size() > cryptofuzz::config::kMaxBignumSize ) {
            return;
        }
        if ( bn2.size() > cryptofuzz::config::kMaxBignumSize ) {
            return;
        }
        if ( bn3.size() > cryptofuzz::config::kMaxBignumSize ) {
            return;
        }

        parameters["calcOp"] = CF_CALCOP("ExpMod(A,B,C)");
        parameters["bn1"] = bn1;
        parameters["bn2"] = bn2;
        parameters["bn3"] = bn3;
    } else {
        CF_UNREACHABLE();
    }

    fuzzing::datasource::Datasource dsOut2(nullptr, 0);
    cryptofuzz::operation::BignumCalc op(parameters);
    op.Serialize(dsOut2);
    write(CF_OPERATION("BignumCalc"), dsOut2);

}

void OpenSSL_Importer::write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2) {
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
