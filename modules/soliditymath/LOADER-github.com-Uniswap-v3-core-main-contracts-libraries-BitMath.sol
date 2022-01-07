// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

import './github.com-Uniswap-v3-core-main-contracts-libraries-BitMath.sol';

contract LOADER_github_com_Uniswap_v3_core_main_contracts_libraries_BitMath {
    function msb(
        uint256 a
    ) public pure returns (uint256 result) {
        return BitMath.mostSignificantBit(a);
    }
    function lsb(
        uint256 a
    ) public pure returns (uint256 result) {
        return BitMath.leastSignificantBit(a);
    }
}
