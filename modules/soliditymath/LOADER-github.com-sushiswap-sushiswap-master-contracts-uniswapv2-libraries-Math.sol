// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

import './github.com-sushiswap-sushiswap-master-contracts-uniswapv2-libraries-Math.sol';

contract LOADER_github_com_sushiswap_sushiswap_master_contracts_uniswapv2_libraries_Math {
    function min(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return Math.min(a,b);
    }
    function sqrt(
        uint256 a
    ) public pure returns (uint256 result) {
        return Math.sqrt(a);
    }
}
