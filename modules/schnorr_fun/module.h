#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class schnorr_fun : public Module {
    public:
        schnorr_fun(void);
        std::optional<bool> OpSchnorr_Verify(operation::Schnorr_Verify& op) override;
        std::optional<component::Schnorr_Signature> OpSchnorr_Sign(operation::Schnorr_Sign& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
