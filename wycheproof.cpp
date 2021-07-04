#include <cryptofuzz/wycheproof.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/operations.h>
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
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
            nlohmann::json
                p_ecdsa_verify,
                p_ecc_point_add,
                p_ecc_point_mul_1,
                p_ecc_point_mul_2,
                p_ecc_validatepubkey_1,
                p_ecc_validatepubkey_2;
            std::string digest;

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

                p_ecdsa_verify["curveType"] = *curveID;
                p_ecc_point_add["curveType"] = *curveID;
                p_ecc_point_mul_1["curveType"] = *curveID;
                p_ecc_point_mul_2["curveType"] = *curveID;
                p_ecc_validatepubkey_1["curveType"] = *curveID;
                p_ecc_validatepubkey_2["curveType"] = *curveID;
            }

            {
                digest = group["sha"];

                if ( digest == "SHA-224") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA224");
                } else if ( digest == "SHA-256") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA256");
                } else if ( digest == "SHA-384") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA384");
                } else if ( digest == "SHA-512") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA512");
                } else if ( digest == "SHA3-224") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA3-224");
                } else if ( digest == "SHA3-256") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA3-256");
                } else if ( digest == "SHA3-384") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA3-384");
                } else if ( digest == "SHA3-512") {
                    p_ecdsa_verify["digestType"] = CF_DIGEST("SHA3-512");
                } else {
                    CF_ASSERT(0, "Digest not recognized");
                }
            }

            p_ecdsa_verify["signature"]["pub"][0] = util::HexToDec(group["key"]["wx"]);
            p_ecdsa_verify["signature"]["pub"][1] = util::HexToDec(group["key"]["wy"]);

            p_ecc_point_add["a_x"] = util::HexToDec(group["key"]["wx"]);
            p_ecc_point_add["a_y"] = util::HexToDec(group["key"]["wy"]);

            p_ecc_point_mul_1["a_x"] = util::HexToDec(group["key"]["wx"]);
            p_ecc_point_mul_1["a_y"] = util::HexToDec(group["key"]["wy"]);

            p_ecc_validatepubkey_1["pub_x"] = util::HexToDec(group["key"]["wx"]);
            p_ecc_validatepubkey_1["pub_y"] = util::HexToDec(group["key"]["wy"]);

            {
                const auto sig = util::SignatureFromDER(test["sig"].get<std::string>());
                CF_CHECK_NE(sig, std::nullopt);

                p_ecdsa_verify["signature"]["signature"][0] = sig->first;
                p_ecdsa_verify["signature"]["signature"][1] = sig->second;

                p_ecc_point_add["b_x"] = sig->first;
                p_ecc_point_add["b_y"] = sig->second;

                p_ecc_point_mul_2["a_x"] = sig->first;
                p_ecc_point_mul_2["a_y"] = sig->second;

                p_ecc_validatepubkey_2["pub_x"] = sig->first;
                p_ecc_validatepubkey_2["pub_y"] = sig->second;
            }

            p_ecdsa_verify["cleartext"] = test["msg"].get<std::string>();

            /* Construct and write ECDSA_Verify */
            {
                p_ecdsa_verify["modifier"] = "";

                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECDSA_Verify op(p_ecdsa_verify);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECDSA_Verify"), dsOut2);
            }

            /* If digest type is SHA256, compute the SHA256 hash of the message,
             * and use this to write an input that uses the NULL digest */
            if ( digest == "SHA-256" ) {
                /* Hex-decode cleartext */
                std::vector<uint8_t> ct_sha256;
                boost::algorithm::unhex(
                        test["msg"].get<std::string>(),
                        std::back_inserter(ct_sha256));
                const auto ct = crypto::sha256(ct_sha256);

                std::string ct_hex;
                boost::algorithm::hex(ct, std::back_inserter(ct_hex));

                p_ecdsa_verify["cleartext"] = ct_hex;
                p_ecdsa_verify["digestType"] = CF_DIGEST("NULL");

                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECDSA_Verify op(p_ecdsa_verify);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECDSA_Verify"), dsOut2);
            }

            {
                p_ecc_point_add["modifier"] = "";

                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECC_Point_Add op(p_ecc_point_add);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECC_Point_Add"), dsOut2);
            }

            {
                p_ecc_point_mul_1["modifier"] = "";
                p_ecc_point_mul_1["b"] = "1";
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECC_Point_Mul op(p_ecc_point_mul_1);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECC_Point_Mul"), dsOut2);
            }

            {
                p_ecc_point_mul_2["modifier"] = "";
                p_ecc_point_mul_2["b"] = "1";
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECC_Point_Mul op(p_ecc_point_mul_2);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECC_Point_Mul"), dsOut2);
            }

            {
                p_ecc_validatepubkey_1["modifier"] = "";
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECC_ValidatePubkey op(p_ecc_validatepubkey_1);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECC_ValidatePubkey"), dsOut2);
            }

            {
                p_ecc_validatepubkey_2["modifier"] = "";
                fuzzing::datasource::Datasource dsOut2(nullptr, 0);
                cryptofuzz::operation::ECC_ValidatePubkey op(p_ecc_validatepubkey_2);
                op.Serialize(dsOut2);

                write(CF_OPERATION("ECC_ValidatePubkey"), dsOut2);
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
