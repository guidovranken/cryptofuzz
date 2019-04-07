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
        std::optional<component::Digest> skein(operation::Digest& op, Datasource& ds, const size_t hashSize) const;
        std::optional<component::Digest> keccak256(operation::Digest& op, Datasource& ds) const;
    public:
        Monero(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
