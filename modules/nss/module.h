#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <nss.h>
#include <pk11pub.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class NSS : public Module {
    private:
        NSSInitContext* nss_context = nullptr;
        std::optional<SECOidTag> toOID(const component::DigestType& digestType) const;
    public:
        NSS(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
