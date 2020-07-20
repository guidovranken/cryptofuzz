#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>
#include <mpdecimal.h>

namespace cryptofuzz {
namespace module {
namespace mpdecimal_bignum {

class Bignum {
    private:
        mpd_context_t* ctx = nullptr;
        mpd_t* mpd = nullptr;
    public:

        Bignum(mpd_context_t* ctx) :
            ctx(ctx) {

            mpd = mpd_new(ctx);
            if ( mpd == nullptr ) {
                abort();
            }
        }

        ~Bignum() {
            mpd_del(mpd);
            mpd = nullptr;
        }

        Bignum(const Bignum& other) {
            ctx = other.ctx;
            mpd = mpd_new(ctx);
            if ( mpd == nullptr ) {
                abort();
            }
            mpd_copy(mpd, other.mpd, ctx);
        }

        Bignum(const Bignum&& other) {
            ctx = other.ctx;
            mpd = mpd_new(ctx);
            if ( mpd == nullptr ) {
                abort();
            }
            mpd_copy(mpd, other.mpd, ctx);
        }

        bool Set(const std::string s) {
            if ( s.empty() ) {
                mpd_set_string(mpd, "0", ctx);
            } else {
                mpd_set_string(mpd, s.c_str(), ctx);
            }
            return true;
        }

        std::optional<std::string> ToString(void) {
            std::optional<std::string> ret = std::nullopt;
            char* c_str;
            std::string str;
            size_t dotpos; 
            uint32_t status = 0;

            c_str = mpd_qformat(mpd, "f", ctx, &status);
            CF_CHECK_EQ(status, 0);

            str = std::string(c_str);

            if ( (dotpos = str.find(".")) == std::string::npos ) {
                ret = str;
            } else {
                ret = str.substr(0, dotpos);
            }

            free(c_str);
end:
            return ret;
        }


        mpd_t* GetPtr(void) {
            return mpd;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;
            const auto s = ToString();
            CF_CHECK_NE(s, std::nullopt);
            ret = { *s };
end:
            return ret;
        }
};

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class And : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Or : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Xor : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Sqrt : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class MulAdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Max : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Min : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

class Log10 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, mpd_context_t* ctx) const override;
};

} /* namespace mpdecimal_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
