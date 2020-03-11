#include <fuzzing/datasource/datasource.hpp>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/repository.h>

#if 0
int main(void)
{
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    /* Operation ID */
    dsOut.Put<uint64_t>(CF_OPERATION("ECDSA_Verify"));
    /* Additional data */
    //dsOut.PutData({0x00});
    {
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        nlohmann::json j;
        j["modifier"] = "";

#if 0
        j["curveType"] = CF_ECC_CURVE("secp224r1");
        j["pub_x"] = "16955619734994862409989689178387898974823941651882707523019895073894";
        j["pub_y"] = "1110809077168273975483954078618568610738298608090022662949972724777";
        j["cleartext"] = "";
        j["sig_x"] = "2947372947142172836863281806455192420255396020594238446629842418694";
        j["sig_y"] = "840523848205885125046172197865156364561232688024846448778643346983";
#endif
        j["curveType"] = CF_ECC_CURVE("x962_p256v1");
        j["pub_x"] = "7959119877524677154445524236551311462989539329942159430802653779400061828938";
        j["pub_y"] = "5363570520037973669821914039576053790435076973969214032148592458358033297031";
        j["cleartext"] = "";
        j["sig_x"] = "66049741600058536741105012648414897459146314171781467629954700649166391299050";
        j["sig_y"] = "92167365964788125853142856067237637748808398135220282907685623834466557198586";

        cryptofuzz::operation::ECDSA_Verify op(j);
        op.Serialize(dsOut2);
        dsOut.PutData(dsOut2.GetOut());
    }
    /* Modifier */
    dsOut.PutData(std::vector<uint8_t>(8192));

    /* Module ID */
    dsOut.Put<uint64_t>(CF_MODULE("OpenSSL"));
    
    /* End of operations */
    dsOut.Put<bool>(false);

    const auto serialized = dsOut.GetOut();
    FILE* fp = fopen("input.bin", "wb");
    fwrite(serialized.data(), serialized.size(), 1, fp);
    fclose(fp);
    //const auto out = dsOut.GetOut();
    //printf("%s\n", cryptofuzz::util::HexDump(out.data(), out.size(), "").c_str());
    return 0;
}
#endif
#if 0
int main(void)
{
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    /* Operation ID */
    dsOut.Put<uint64_t>(CF_OPERATION("ECDSA_Sign"));
    /* Additional data */
    //dsOut.PutData({0x00});
    {
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        nlohmann::json j;
        j["modifier"] = "";
        j["curveType"] = CF_ECC_CURVE("secp224r1");
        j["priv"] = "2366845160746415442977209804256233241592441766424164253221602252309";
        j["cleartext"] = "";

        cryptofuzz::operation::ECDSA_Sign op(j);
        op.Serialize(dsOut2);
        dsOut.PutData(dsOut2.GetOut());
    }
    /* Modifier */
    dsOut.PutData(std::vector<uint8_t>(8192));

    /* Module ID */
    dsOut.Put<uint64_t>(CF_MODULE("OpenSSL"));
    
    /* End of operations */
    dsOut.Put<bool>(false);

    const auto serialized = dsOut.GetOut();
    FILE* fp = fopen("input_ecdsa_sign.bin", "wb");
    fwrite(serialized.data(), serialized.size(), 1, fp);
    fclose(fp);
    //const auto out = dsOut.GetOut();
    //printf("%s\n", cryptofuzz::util::HexDump(out.data(), out.size(), "").c_str());
    return 0;
}
#endif
#if 1
int main(void)
{
    fuzzing::datasource::Datasource dsOut(nullptr, 0);

    /* Operation ID */
    dsOut.Put<uint64_t>(CF_OPERATION("ECDH_Derive"));
    /* Additional data */
    //dsOut.PutData({0x00});
    {
        fuzzing::datasource::Datasource dsOut2(nullptr, 0);
        nlohmann::json j;
        j["modifier"] = "";
        j["curveType"] = CF_ECC_CURVE("x962_p256v1");
        j["pub1_x"] = "106212412493551342293322570238892315031616341549188260455891278386227042497072";
        j["pub1_y"] = "18402382730812010921741766723531906580711424967970260075714717879926987444545";
        j["pub2_x"] = "50680744804357153096339642489054523933459029029467910410636571659873721504391";
        j["pub2_y"] = "99257748324618449011876249978940495395579669768149646770406575920953641903276";

        cryptofuzz::operation::ECDH_Derive op(j);
        op.Serialize(dsOut2);
        dsOut.PutData(dsOut2.GetOut());

        {
            auto out = dsOut2.GetOut();
            printf("out size %zu\n", out.size());
            fuzzing::datasource::Datasource x(out.data(), out.size());
            cryptofuzz::operation::ECDH_Derive op2(x, {});
            if ( !(op == op2) ) abort();
        }
    }
    /* Modifier */
    dsOut.PutData(std::vector<uint8_t>(8192));

    /* Only required for ECDH_Derive */
    dsOut.Put<bool>(false);

    /* Module ID */
    dsOut.Put<uint64_t>(CF_MODULE("OpenSSL"));
    
    /* End of operations */
    dsOut.Put<bool>(false);

    const auto serialized = dsOut.GetOut();
    FILE* fp = fopen("input.bin", "wb");
    fwrite(serialized.data(), serialized.size(), 1, fp);
    fclose(fp);
    //const auto out = dsOut.GetOut();
    //printf("%s\n", cryptofuzz::util::HexDump(out.data(), out.size(), "").c_str());
    return 0;
}
#endif
