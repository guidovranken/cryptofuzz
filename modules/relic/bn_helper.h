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
        Datasource& ds;
        bn_t bn;
        void baseConversion(void);
    public:
        Bignum(Datasource& ds);
        Bignum(const Bignum& other);
        Bignum(const Bignum&& other);
        bool Set(const std::string& s);
        std::optional<std::string> ToString(void);
        std::optional<component::Bignum> ToComponentBignum(void);
        std::optional<int> ToInt(void);
        bn_t& Get(void);
        ~Bignum(void);
};

} /* namespace relic_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
