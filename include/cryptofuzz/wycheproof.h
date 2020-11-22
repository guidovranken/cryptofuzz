#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class Wycheproof {
    private:
        nlohmann::json j;
        const std::string outDir;
        void ECDSA_Verify(const nlohmann::json& groups);
        void EDDSA_Verify(const nlohmann::json& groups);
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
    public:
        Wycheproof(const std::string filename, const std::string outDir);
        void Run(void);
};

} /* namespace cryptofuzz */
