// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

import './github.com-Uniswap-v3-core-main-contracts-libraries-LowGasSafeMath.sol';

contract LOADER_github_com_Uniswap_v3_core_main_contracts_libraries_LowGasSafeMath {
    function add(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return LowGasSafeMath.add(a,b);
    }
    function sub(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return LowGasSafeMath.sub(a,b);
    }
    function mul(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return LowGasSafeMath.mul(a,b);
    }
}
