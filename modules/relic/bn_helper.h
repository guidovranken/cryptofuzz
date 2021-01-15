#include <optional>
#include <cryptofuzz/components.h>

extern "C" {
    #include <relic_conf.h>
    #include <relic.h>
}

namespace cryptofuzz {
namespace module {
namespace relic_bignum {

class Bignum {
    private:
        bn_t bn;
    public:
        Bignum(void);
        bool Set(const std::string& s);
        std::optional<std::string> ToString(void);
        std::optional<component::Bignum> ToComponentBignum(void);
        bn_t& Get(void);
        ~Bignum(void);
};

} /* namespace relic_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
