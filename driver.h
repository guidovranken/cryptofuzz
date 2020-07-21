#pragma once

#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <cryptofuzz/module.h>
#include <cryptofuzz/options.h>
#include <memory>
#include <map>
#include <vector>
#include <utility>

namespace cryptofuzz {

class Driver {
    private:
        std::map<uint64_t, std::shared_ptr<Module> > modules;
        Options options;
    public:
        void LoadModule(std::shared_ptr<Module> module);
        void Run(const uint8_t* data, const size_t size) const;
        Driver(const Options options);
};

} /* namespace cryptofuzz */
