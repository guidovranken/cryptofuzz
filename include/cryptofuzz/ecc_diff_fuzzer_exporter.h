#pragma once

#include "../../third_party/json/json.hpp"
#include <string>
#include <fuzzing/datasource/datasource.hpp>

namespace cryptofuzz {

class ECC_Diff_Fuzzer_Exporter {
    private:
        const std::string filename;
        const std::string outDir;
        void LoadInput(const std::vector<uint8_t> data);
        void write_Add(
                const uint64_t curveType,
                const std::string ax,
                const std::string ay,
                const std::string bx,
                const std::string by);
        void write_Mul(
                const uint64_t curveType,
                const std::string ax,
                const std::string ay,
                const std::string b);
        void write(const std::vector<uint8_t> data);
    public:
        ECC_Diff_Fuzzer_Exporter(const std::string filename, const std::string outDir);
        void Run(void);
};

} /* namespace cryptofuzz */
