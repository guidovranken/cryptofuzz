#include <cryptofuzz/bignum_fuzzer_importer.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <stdio.h>
#include <fstream>
#include "config.h"

namespace cryptofuzz {

Bignum_Fuzzer_Importer::Bignum_Fuzzer_Importer(const std::string filename, const std::string outDir) :
    filename(filename), outDir(outDir) {
}

void Bignum_Fuzzer_Importer::Run(void) {
    std::ifstream instream(filename, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    LoadInput(data);
}

static std::string bignum_from_bin(const uint8_t* data, size_t size) {
    std::string ret;
    for (size_t i = 0; i < size; i++) {
        ret += data[i] % 10 + '0';
    }

    return ret;
}

void Bignum_Fuzzer_Importer::LoadInput(const std::vector<uint8_t> data) {
    uint8_t bignums[4][1200];

    if ( data.size() < sizeof(bignums) ) {
        return;
    }

    memcpy(bignums, data.data(), sizeof(bignums));

    const auto bn1 = bignum_from_bin(bignums[0], 1200);
    const auto bn2 = bignum_from_bin(bignums[1], 1200);
    const auto bn3 = bignum_from_bin(bignums[2], 1200);
    const auto bn4 = bignum_from_bin(bignums[3], 1200);

    const std::vector<uint64_t> calcops = {
        CF_CALCOP("Add(A,B)"),
        CF_CALCOP("Sub(A,B)"),
        CF_CALCOP("Mul(A,B)"),
        CF_CALCOP("Div(A,B)"),
        CF_CALCOP("Mod(A,B)"),
        CF_CALCOP("ExpMod(A,B,C)"),
        CF_CALCOP("LShift1(A)"),
        CF_CALCOP("RShift(A,B)"),
        CF_CALCOP("RShift(A,B)"),
        CF_CALCOP("GCD(A,B)"),
        CF_CALCOP("AddMod(A,B,C)"),
        CF_CALCOP("Exp(A,B)"),
        CF_CALCOP("Cmp(A,B)"),
        CF_CALCOP("Sqr(A)"),
        CF_CALCOP("Neg(A)"),
        CF_CALCOP("Abs(A)"),
        CF_CALCOP("IsPrime(A)"),
        CF_CALCOP("SubMod(A,B,C)"),
        CF_CALCOP("MulMod(A,B,C)"),
        CF_CALCOP("SetBit(A,B)"),
    };

    for (const auto& calcop : calcops) {
        nlohmann::json parameters;

        parameters["modifier"] = "";
        parameters["calcOp"] = calcop;
        parameters["bn1"] = bn1;
        parameters["bn2"] = bn2;
        parameters["bn3"] = bn3;
        parameters["bn4"] = bn4;

        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        cryptofuzz::operation::BignumCalc op(parameters);
        op.Serialize(dsOut2);
        write(CF_OPERATION("BignumCalc"), dsOut2);
    }
}

void Bignum_Fuzzer_Importer::write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2) {
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
