#pragma once

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {
    int wc_Check(const int ret);
} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */

#define WC_CHECK_EQ(expr, res) CF_CHECK_EQ(::cryptofuzz::module::wolfCrypt_detail::wc_Check(expr), res);
