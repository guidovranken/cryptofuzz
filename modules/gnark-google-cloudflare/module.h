#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include "../../third_party/json/json.hpp"
#include <optional>

namespace cryptofuzz {
namespace module {

class Gnark_bn254 : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        Gnark_bn254(void);
        std::optional<bool> OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) override;
        std::optional<bool> OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) override;
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op) override;
        std::optional<component::G2> OpBLS_G2_Neg(operation::BLS_G2_Neg& op) override;
        std::optional<component::Fp12> OpBLS_Pairing(operation::BLS_Pairing& op) override;
        std::optional<component::Fp12> OpBLS_FinalExp(operation::BLS_FinalExp& op) override;
        std::optional<component::G1> OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) override;
        std::optional<component::Fp2> OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) override;
        std::optional<component::Fp12> OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) override;
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) override;
        bool SupportsModularBignumCalc(void) const override;
};

class Cloudflare_bn256 : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        Cloudflare_bn256(void);
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op) override;
        std::optional<component::G2> OpBLS_G2_Neg(operation::BLS_G2_Neg& op) override;
        std::optional<component::Fp12> OpBLS_FinalExp(operation::BLS_FinalExp& op) override;
};

class Google_bn256 : public Module {
    private:
        std::string getResult(void) const;
        std::optional<nlohmann::json> getJsonResult(void) const;

        template <class T> std::optional<T> getResultAs(void) const;
    public:
        Google_bn256(void);
        std::optional<component::G1> OpBLS_G1_Add(operation::BLS_G1_Add& op) override;
        std::optional<component::G1> OpBLS_G1_Mul(operation::BLS_G1_Mul& op) override;
        std::optional<component::G1> OpBLS_G1_Neg(operation::BLS_G1_Neg& op) override;
        std::optional<component::G2> OpBLS_G2_Add(operation::BLS_G2_Add& op) override;
        std::optional<component::G2> OpBLS_G2_Mul(operation::BLS_G2_Mul& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */
