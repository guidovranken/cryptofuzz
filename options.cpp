#include <cryptofuzz/options.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <iostream>
#include <stdlib.h>
#include <cryptofuzz/repository.h>
#include <cryptofuzz/wycheproof.h>
#include <cryptofuzz/ecc_diff_fuzzer_importer.h>
#include <cryptofuzz/botan_importer.h>
#include <cryptofuzz/util.h>

namespace cryptofuzz {

bool EnabledTypes::Have(const uint64_t id) const {
    return types.empty() || HaveExplicit(id);
}

bool EnabledTypes::HaveExplicit(const uint64_t id) const {
    return types.find(id) != types.end();
}

void EnabledTypes::Add(const uint64_t id) {
    types.insert(id);
}

uint64_t EnabledTypes::At(const size_t index) const {
    CF_ASSERT(!Empty(), "Calling At on empty container");

    std::set<uint64_t>::const_iterator it = types.begin();
    std::advance(it, index % types.size());

    return *it;
}

bool EnabledTypes::Empty(void) const {
    return types.empty();
}

std::string Options::calcOpToBase(const std::string calcOp) {
    std::vector<std::string> calcOpParts;
    boost::split(calcOpParts, calcOp, boost::is_any_of("("));
    if ( calcOpParts.empty() ) {
        printf("Cannot parse calcop\n");
        abort();
    }
    return calcOpParts[0];
}

Options::Options(const int argc, char** argv, const std::vector<std::string> extraArguments) {
    for (int i = 0; i < argc; i++) {
        arguments.push_back( std::string(argv[i]) );
    }

    arguments.insert(arguments.end(), extraArguments.begin(), extraArguments.end());

    for (size_t i = 1; i < arguments.size(); i++) {
        const auto arg = arguments[i];
        std::vector<std::string> parts;
        boost::split(parts, arg, boost::is_any_of("="));

        if ( arg == "--debug" ) {
            debug = true;
        } else if ( !parts.empty() && parts[0] == "--operations" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --operations=" << std::endl;
                exit(1);
            }

            std::vector<std::string> operationStrings;
            boost::split(operationStrings, parts[1], boost::is_any_of(","));

            for (const auto& curOpStr : operationStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::OperationLUT) / sizeof(repository::OperationLUT[0])); i++) {
                    if ( boost::iequals(curOpStr, std::string(repository::OperationLUT[i].name)) ) {
                        this->operations.Add(repository::OperationLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined operation: " << curOpStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--ciphers" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --ciphers=" << std::endl;
                exit(1);
            }

            std::vector<std::string> cipherStrings;
            boost::split(cipherStrings, parts[1], boost::is_any_of(","));

            for (const auto& curOpStr : cipherStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::CipherLUT) / sizeof(repository::CipherLUT[0])); i++) {
                    if ( boost::iequals(curOpStr, std::string(repository::CipherLUT[i].name)) ) {
                        this->ciphers.Add(repository::CipherLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined cipher: " << curOpStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--digests" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --digests=" << std::endl;
                exit(1);
            }

            std::vector<std::string> digestStrings;
            boost::split(digestStrings, parts[1], boost::is_any_of(","));

            for (const auto& curOpStr : digestStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::DigestLUT) / sizeof(repository::DigestLUT[0])); i++) {
                    if ( boost::iequals(curOpStr, std::string(repository::DigestLUT[i].name)) ) {
                        this->digests.Add(repository::DigestLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined digest: " << curOpStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--curves" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --curves=" << std::endl;
                exit(1);
            }

            std::vector<std::string> curveStrings;
            boost::split(curveStrings, parts[1], boost::is_any_of(","));

            for (const auto& curOpStr : curveStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::ECC_CurveLUT) / sizeof(repository::ECC_CurveLUT[0])); i++) {
                    if ( boost::iequals(curOpStr, std::string(repository::ECC_CurveLUT[i].name)) ) {
                        this->curves.Add(repository::ECC_CurveLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined curve: " << curOpStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--force-module" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --force-module=" << std::endl;
                exit(1);
            }

            const auto& moduleStr = parts[1];

            bool found = false;
            uint64_t forceModule;
            for (size_t i = 0; i < (sizeof(repository::ModuleLUT) / sizeof(repository::ModuleLUT[0])); i++) {
                if ( boost::iequals(moduleStr, std::string(repository::ModuleLUT[i].name)) ) {
                    forceModule = repository::ModuleLUT[i].id;
                    found = true;
                    break;
                }
            }

            if ( found == false ) {
                std::cout << "Undefined module: " << moduleStr << std::endl;
                exit(1);
            }

            this->forceModule = forceModule;
        } else if ( !parts.empty() && parts[0] == "--disable-modules" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --disable-modules=" << std::endl;
                exit(1);
            }

            std::vector<std::string> moduleStrings;
            boost::split(moduleStrings, parts[1], boost::is_any_of(","));

            for (const auto& curModStr : moduleStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::ModuleLUT) / sizeof(repository::ModuleLUT[0])); i++) {
                    if ( boost::iequals(curModStr, std::string(repository::ModuleLUT[i].name)) ) {
                        this->disableModules.Add(repository::ModuleLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined module: " << curModStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--calcops" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --calcops=" << std::endl;
                exit(1);
            }

            std::vector<std::string> calcOpStrings;
            boost::split(calcOpStrings, parts[1], boost::is_any_of(","));

            for (const auto& curCalcOpStr : calcOpStrings) {
                bool found = false;
                for (size_t i = 0; i < (sizeof(repository::CalcOpLUT) / sizeof(repository::CalcOpLUT[0])); i++) {
                    if ( boost::iequals(curCalcOpStr, calcOpToBase(repository::CalcOpLUT[i].name)) ) {
                        this->calcOps.Add(repository::CalcOpLUT[i].id);
                        found = true;
                        break;
                    }
                }

                if ( found == false ) {
                    std::cout << "Undefined calc op: " << curCalcOpStr << std::endl;
                    exit(1);
                }
            }
        } else if ( !parts.empty() && parts[0] == "--min-modules" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --min-modules=" << std::endl;
                exit(1);
            }

            const auto& moduleStr = parts[1];
            const int minModules = stoi(moduleStr);
            if ( minModules < 1 ) {
                std::cout << "min-modules must be >= 1" << std::endl;
                exit(1);
            }

            this->minModules = static_cast<size_t>(minModules);
        } else if ( !parts.empty() && parts[0] == "--disable-tests" ) {
            if ( parts.size() != 1 ) {
                std::cout << "Expected no argument after --disable-tests=" << std::endl;
                exit(1);
            }
            this->disableTests = true;
        } else if ( !parts.empty() && parts[0] == "--no-decrypt" ) {
            if ( parts.size() != 1 ) {
                std::cout << "Expected no argument after --no-decrypt=" << std::endl;
                exit(1);
            }
            this->noDecrypt = true;
        } else if ( !parts.empty() && parts[0] == "--no-compare" ) {
            if ( parts.size() != 1 ) {
                std::cout << "Expected no argument after --no-compare=" << std::endl;
                exit(1);
            }
            this->noCompare = true;
        } else if ( !parts.empty() && parts[0] == "--dump-json" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --dump-json=" << std::endl;
                exit(1);
            }

            const auto jsonPath = parts[1];

            FILE* fp = fopen(jsonPath.c_str(), "wb");
            if ( fp == nullptr ) {
                std::cout << "Cannot open file " << jsonPath << std::endl;
                exit(1);
            }
            this->jsonDumpFP = fp;
        } else if ( !parts.empty() && parts[0] == "--from-wycheproof" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --from-wycheproof=" << std::endl;
                exit(1);
            }

            std::vector<std::string> wycheproofArgs;
            boost::split(wycheproofArgs, parts[1], boost::is_any_of(","));

            if ( wycheproofArgs.size() != 2 ) {
                std::cout << "Expected 2 arguments after --from-wycheproof=" << std::endl;
                exit(1);
            }

            Wycheproof wp(wycheproofArgs[0], wycheproofArgs[1]);
            wp.Run();

            exit(0);
#if defined(CRYPTOFUZZ_IMPORT_ECC_DIFF_FUZZER)
        } else if ( !parts.empty() && parts[0] == "--from-ecc-diff-fuzzer" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --from-ecc-diff-fuzzer=" << std::endl;
                exit(1);
            }

            std::vector<std::string> args;
            boost::split(args, parts[1], boost::is_any_of(","));

            if ( args.size() != 2 ) {
                std::cout << "Expected 2 arguments after --from-ecc-diff-fuzzer=" << std::endl;
                exit(1);
            }

            ECC_Diff_Fuzzer_Importer importer(args[0], args[1]);
            importer.Run();

            exit(0);
#endif
        } else if ( !parts.empty() && parts[0] == "--from-botan" ) {
            if ( parts.size() != 2 ) {
                std::cout << "Expected argument after --from-botan=" << std::endl;
                exit(1);
            }

            std::vector<std::string> args;
            boost::split(args, parts[1], boost::is_any_of(","));

            if ( args.size() != 3 ) {
                std::cout << "Expected 3 arguments after --from-botan=" << std::endl;
                exit(1);
            }

            const auto curveID = repository::ECC_CurveFromString(args[2]);
            CF_ASSERT(curveID != std::nullopt, "Unknown curve");

            Botan_Importer importer(args[0], args[1], *curveID);
            importer.Run();

            exit(0);
        }
    }
}

} /* namespace cryptofuzz */
