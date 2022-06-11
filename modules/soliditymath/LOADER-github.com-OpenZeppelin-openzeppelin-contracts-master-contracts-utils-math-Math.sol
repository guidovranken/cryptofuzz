// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

import './github.com-OpenZeppelin-openzeppelin-contracts-master-contracts-utils-math-Math.sol';

contract LOADER_github_com_OpenZeppelin_openzeppelin_contracts_master_contracts_utils_math_Math {
    function min(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return Math.min(a,b);
    }
    function max(
        uint256 a,
        uint256 b
    ) public pure returns (uint256 result) {
        return Math.max(a,b);
    }
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) public pure returns (uint256 result) {
        return Math.mulDiv(a, b, denominator, Math.Rounding.Down);
    }
    function mulDivCeil(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) public pure returns (uint256 result) {
        return Math.mulDiv(a, b, denominator, Math.Rounding.Up);
    }
    function sqrt(
        uint256 a
    ) public pure returns (uint256 result) {
        return Math.sqrt(a, Math.Rounding.Down);
    }
    function sqrtCeil(
        uint256 a
    ) public pure returns (uint256 result) {
        return Math.sqrt(a, Math.Rounding.Up);
    }
}
