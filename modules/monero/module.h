#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class Monero : public Module {
    private:
        std::optional<component::Digest> groestl(operation::Digest& op, Datasource& ds) const;
        std::optional<component::Digest> jh(operation::Digest& op, Datasource& ds, const size_t hashSize) const;
    public:
        Monero(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
