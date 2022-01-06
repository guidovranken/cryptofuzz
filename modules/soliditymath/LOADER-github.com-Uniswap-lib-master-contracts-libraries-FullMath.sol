// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

import './github.com-Uniswap-lib-master-contracts-libraries-FullMath.sol';

contract LOADER_github_com_Uniswap_lib_master_contracts_libraries_FullMath {
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) public pure returns (uint256 result) {
        return FullMath.mulDiv(a, b, denominator);
    }
}
