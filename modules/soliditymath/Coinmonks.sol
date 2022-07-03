// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/* From https://medium.com/coinmonks/math-in-solidity-part-3-percents-and-proportions-4db014e080b1 */

contract Coinmonks {
    function fullMul (uint x, uint y)
        private pure returns (uint l, uint h)
        {
            uint mm = mulmod (x, y, uint (-1));
            l = x * y;
            h = mm - l;
            if (mm < l) h -= 1;
        }

    function mulDiv (uint x, uint y, uint z)
        public pure returns (uint) {
            (uint l, uint h) = fullMul (x, y);
            require (h < z);
            uint mm = mulmod (x, y, z);
            if (mm > l) h -= 1;
            l -= mm;
            uint pow2 = z & -z;
            z /= pow2;
            l /= pow2;
            l += h * ((-pow2) / pow2 + 1);
            uint r = 1;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            r *= 2 - z * r;
            return l * r;
        }
}
