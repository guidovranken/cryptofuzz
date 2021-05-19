#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"
#include <optional>

namespace cryptofuzz {
namespace module {

class kilic_bls12_381 : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        kilic_bls12_381(void);
        std::optional<component::BLS_PublicKey> OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) override;
        std::optional<component::G2> OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
