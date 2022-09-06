#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"
#include <optional>

namespace cryptofuzz {
namespace module {

class Decred : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        Decred(void);
        std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) override;
        std::optional<bool> OpECDSA_Verify(operation::ECDSA_Verify& op) override;
        std::optional<component::ECDSA_Signature> OpECDSA_Sign(operation::ECDSA_Sign& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
