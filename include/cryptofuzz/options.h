#pragma once

#include <stdio.h>
#include <string>
#include <vector>
#include <set>
#include <optional>
#include <cstdint>

namespace cryptofuzz {

class EnabledTypes {
    private:
        std::set<uint64_t> types;
    public:
        bool Have(const uint64_t id) const;
        bool HaveExplicit(const uint64_t id) const;
        void Add(const uint64_t id);
        uint64_t At(const size_t index) const;
        bool Empty(void) const;
};

class Options {
    private:
        std::vector<std::string> arguments;
        std::string calcOpToBase(const std::string calcOp);
    public:
        Options(const int argc, char** argv, const std::vector<std::string> extraArguments = {});

        EnabledTypes operations, ciphers, digests, curves, calcOps, disableModules;
        std::optional<uint64_t> forceModule = std::nullopt;
        std::optional<FILE*> jsonDumpFP = std::nullopt;
        size_t minModules = 1;
        bool debug = false;
        bool disableTests = false;
        bool noDecrypt = false;
        bool noCompare = false;
};

} /* namespace cryptofuzz */
