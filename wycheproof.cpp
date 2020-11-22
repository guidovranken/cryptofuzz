#include <cryptofuzz/wycheproof.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <stdio.h>
#include <fstream>

namespace cryptofuzz {

Wycheproof::Wycheproof(const std::string filename, const std::string outDir) :
    outDir(outDir) {
    std::ifstream ifs(filename);
    j = nlohmann::json::parse(ifs);
}
        
void Wycheproof::Run(void) {
    const auto& groups = j["testGroups"];

    if ( j["schema"].get<std::string>() == "ecdsa_verify_schema.json" ) {
        ECDSA_Verify(groups);
    } else if ( j["schema"].get<std::string>() == "eddsa_verify_schema.json" ) {
        EDDSA_Verify(groups);
    }
}
        
void Wycheproof::write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2) {
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
        //std::string filename = outDir + std::string("/") + std::to_string(counter++);
        std::string filename = outDir + std::string("/") + util::SHA1(dsOut.GetOut());
        FILE* fp = fopen(filename.c_str(), "wb");
        fwrite(dsOut.GetOut().data(), dsOut.GetOut().size(), 1, fp);
        fclose(fp);
    }
}

void Wycheproof::ECDSA_Verify(const nlohmann::json& groups) {
    for (const auto &group : groups) {
        for (const auto &test : group["tests"]) {
            nlohmann::json parameters;

            {
                const std::string curve = group["key"]["curve"];
                auto curveID = repository::ECC_CurveFromString(curve);

                if ( curveID == std::nullopt ) {
                    if ( curve == "brainpoolP224r1" ) {
                        curveID = CF_ECC_CURVE("brainpool224r1");
                    } else if ( curve == "brainpoolP224t1" ) {
                        curveID = CF_ECC_CURVE("brainpool224t1");
                    } else if ( curve == "brainpoolP256r1" ) {
                        curveID = CF_ECC_CURVE("brainpool256r1");
                    } else if ( curve == "brainpoolP256t1" ) {
                        curveID = CF_ECC_CURVE("brainpool256t1");
                    } else if ( curve == "brainpoolP320r1" ) {
                        curveID = CF_ECC_CURVE("brainpool320r1");
                    } else if ( curve == "brainpoolP320t1" ) {
                        curveID = CF_ECC_CURVE("brainpool320t1");
                    } else if ( curve == "brainpoolP384r1" ) {
                        curveID = CF_ECC_CURVE("brainpool384r1");
                    } else if ( curve == "brainpoolP384t1" ) {
                        curveID = CF_ECC_CURVE("brainpool384t1");
                    } else if ( curve == "brainpoolP512r1" ) {
                        curveID = CF_ECC_CURVE("brainpool512r1");
                    } else if ( curve == "brainpoolP512t1" ) {
                        curveID = CF_ECC_CURVE("brainpool512t1");
                    } else {
                        CF_ASSERT(0, "Curve not recognized");
                    }
                }

                parameters["curveType"] = *curveID;
            }

            {
                const std::string digest = group["sha"];
                if ( digest == "SHA-224") {
                    parameters["digestType"] = CF_DIGEST("SHA224");
                } else if ( digest == "SHA-256") {
                    parameters["digestType"] = CF_DIGEST("SHA256");
                } else if ( digest == "SHA-384") {
                    parameters["digestType"] = CF_DIGEST("SHA384");
                } else if ( digest == "SHA-512") {
                    parameters["digestType"] = CF_DIGEST("SHA512");
                } else if ( digest == "SHA3-224") {
                    parameters["digestType"] = CF_DIGEST("SHA3-224");
                } else if ( digest == "SHA3-256") {
                    parameters["digestType"] = CF_DIGEST("SHA3-256");
                } else if ( digest == "SHA3-384") {
                    parameters["digestType"] = CF_DIGEST("SHA3-384");
                } else if ( digest == "SHA3-512") {
                    parameters["digestType"] = CF_DIGEST("SHA3-512");
                } else {
                    CF_ASSERT(0, "Digest not recognized");
                }
            }

            parameters["signature"]["pub"][0] = util::HexToDec(group["key"]["wx"]);
            parameters["signature"]["pub"][1] = util::HexToDec(group["key"]["wy"]);

            {
                const auto sig = util::SignatureFromDER(test["sig"].get<std::string>());
                CF_CHECK_NE(sig, std::nullopt);

                parameters["signature"]["signature"][0] = sig->first;
                parameters["signature"]["signature"][1] = sig->second;
            }

            parameters["cleartext"] = test["msg"].get<std::string>();

            parameters["modifier"] = std::string(1000, '0');
            {
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECDSA_Verify op(parameters);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECDSA_Verify"), dsOut2);
            }

end:
            (void)1;
        }
    }
}

void Wycheproof::EDDSA_Verify(const nlohmann::json& groups) {
    for (const auto &group : groups) {
        for (const auto &test : group["tests"]) {
            nlohmann::json parameters;

            {
                const std::string curve = group["key"]["curve"];

                if ( curve == "edwards448" ) {
                    parameters["curveType"] = CF_ECC_CURVE("ed448");
                } else {
                    CF_ASSERT(0, "Curve not recognized");
                }
            }

            parameters["digestType"] = CF_DIGEST("NULL");

            parameters["signature"]["pub"][0] = util::HexToDec(group["key"]["pk"]);
            parameters["signature"]["pub"][1] = "0";

            {
                const auto sig = test["sig"].get<std::string>();
                CF_CHECK_EQ(sig.size() % 4, 0);

                const auto R = std::string(sig.data(), sig.data() + (sig.size() / 2));
                const auto S = std::string(sig.data() + (sig.size() / 2), sig.data() + sig.size());

                parameters["signature"]["signature"][0] = util::HexToDec(R);
                parameters["signature"]["signature"][1] = util::HexToDec(S);
            }

            parameters["cleartext"] = test["msg"].get<std::string>();

            parameters["modifier"] = std::string(1000, '0');
            {
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECDSA_Verify op(parameters);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECDSA_Verify"), dsOut2);
            }

end:
            (void)1;
        }
    }
}

} /* namespace cryptofuzz */
