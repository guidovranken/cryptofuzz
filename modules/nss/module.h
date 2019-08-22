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
        std::optional<SECOidTag> toOID(const component::DigestType& digestType) const;
        std::optional<CK_MECHANISM_TYPE> toHMACCKM(const component::DigestType& digestType) const;
    public:
        NSS(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
        std::optional<component::MAC> OpHMAC(operation::HMAC& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
