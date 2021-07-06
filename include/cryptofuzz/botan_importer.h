#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class Botan_Importer {
    private:
        const std::string filename;
        const std::string outDir;
        const uint64_t curveId;
        void LoadInput(const std::vector<uint8_t> data);
        void write(const uint64_t operation, fuzzing::datasource::Datasource& dsOut2);
    public:
        Botan_Importer(const std::string filename, const std::string outDir, const uint64_t curveId);
        void Run(void);
};

} /* namespace cryptofuzz */
