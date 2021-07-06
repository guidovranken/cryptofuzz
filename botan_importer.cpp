#include <cryptofuzz/botan_importer.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <stdio.h>
#include <fstream>

namespace cryptofuzz {

Botan_Importer::Botan_Importer(const std::string filename, const std::string outDir, const uint64_t curveId) :
    filename(filename), outDir(outDir), curveId(curveId) {
}

void Botan_Importer::Run(void) {
    std::ifstream instream(filename, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

    LoadInput(data);
}

void Botan_Importer::LoadInput(const std::vector<uint8_t> data) {

   switch ( curveId ) {
       case CF_ECC_CURVE("brainpool256r1"):
           if ( data.size() > 2*256/8 ) {
               return;
           }
           break;
       case CF_ECC_CURVE("secp256r1"):
           if ( data.size() > 2*256/8 ) {
               return;
           }
           break;
       case CF_ECC_CURVE("secp384r1"):
           if ( data.size() > 2*384/8 ) {
               return;
           }
           break;
       case CF_ECC_CURVE("secp521r1"):
           if ( data.size() > 2*(521+7)/8 ) {
               return;
           }
           break;
       default:
           CF_ASSERT(0, "Curve not supported");
   }

   const auto a_x = *repository::ECC_CurveToX(curveId);
   const auto a_y = *repository::ECC_CurveToY(curveId);

   const size_t half = data.size() / 2;
   const std::array<std::string, 2> multipliers = {
       cryptofuzz::util::BinToDec(data.data(), half),
       cryptofuzz::util::BinToDec(data.data() + half, half)
   };

   for (const auto& multiplier : multipliers) {
       nlohmann::json parameters;
       parameters["modifier"] = "";
       parameters["curveType"] = curveId;
       parameters["a_x"] = a_x;
       parameters["a_y"] = a_y;
       parameters["b"] = multiplier;
       fuzzing::datasource::Datasource dsOut2(nullptr, 0);
       cryptofuzz::operation::ECC_Point_Mul op(parameters);
       op.Serialize(dsOut2);
       write(CF_OPERATION("ECC_Point_Mul"), dsOut2);
   }
}

void Botan_Importer::write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2) {
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
