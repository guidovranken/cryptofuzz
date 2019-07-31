#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"

namespace cryptofuzz {
namespace module {

class Golang : public Module {
    private:
        std::string getResult(void) const;
        nlohmann::json getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        Golang(void);
        std::optional<component::Digest> OpDigest(operation::Digest& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
