//SPDX-License-Identifier: Unlicense
pragma solidity 0.6.10;
pragma experimental ABIEncoderV2;

import "./utils/FieldOperations.sol";
import "./utils/Precompiled.sol";
import "./utils/FractionUtils.sol";
import "./SkaleVerifier.sol";

contract Cryptofuzz {
    function BLS_IsG1OnCurve(uint x, uint y) public pure returns (bool) {
        return G1Operations.isG1Point(x, y);
    }
    function BLS_IsG2OnCurve(G2Operations.G2Point calldata g2) public pure returns (bool) {
        return G2Operations.isG2(g2);
    }
    function BLS_G2_IsEq(G2Operations.G2Point calldata a, G2Operations.G2Point calldata b) public pure returns (bool) {
        return G2Operations.isEqual(a, b);
    }
    function BLS_G2_Add(G2Operations.G2Point calldata a, G2Operations.G2Point calldata b) public view returns (G2Operations.G2Point memory) {
        return G2Operations.addG2(a, b);
    }
    function BLS_G2_Double(G2Operations.G2Point calldata a) public view returns (G2Operations.G2Point memory) {
        return G2Operations.doubleG2(a);
    }
    function BLS_BignumCalc_Fp2_Add(Fp2Operations.Fp2Point memory a, Fp2Operations.Fp2Point memory b) public pure returns (Fp2Operations.Fp2Point memory) {
        return Fp2Operations.addFp2(a, b);
    }
    function BLS_BignumCalc_Fp2_Sub(Fp2Operations.Fp2Point memory a, Fp2Operations.Fp2Point memory b) public pure returns (Fp2Operations.Fp2Point memory) {
        return Fp2Operations.minusFp2(a, b);
    }
    function BLS_BignumCalc_Fp2_Mul(Fp2Operations.Fp2Point memory a, Fp2Operations.Fp2Point memory b) public pure returns (Fp2Operations.Fp2Point memory) {
        return Fp2Operations.mulFp2(a, b);
    }
    function BLS_BignumCalc_Fp2_InvMod(Fp2Operations.Fp2Point memory fp2) public view returns (Fp2Operations.Fp2Point memory) {
        return Fp2Operations.inverseFp2(fp2);
    }
    function BLS_BignumCalc_Fp2_Sqr(Fp2Operations.Fp2Point memory fp2) public pure returns (Fp2Operations.Fp2Point memory) {
        return Fp2Operations.squaredFp2(fp2);
    }
    function BLS_BignumCalc_Fp2_IsEq(Fp2Operations.Fp2Point memory a, Fp2Operations.Fp2Point memory b) public pure returns (bool) {
        return Fp2Operations.isEqual(a, b);
    }
    function BLS_BignumCalc_ExpMod(uint base, uint power, uint modulus) public view returns (uint) {
        return Precompiled.bigModExp(base, power, modulus);
    }
    function BLS_BignumCalc_GCD(uint a, uint b) public pure returns (uint) {
        return FractionUtils.gcd(a, b);
    }
    function Verify(
        Fp2Operations.Fp2Point calldata signature,
        bytes32 hash,
        uint counter,
        uint hashA,
        uint hashB,
        G2Operations.G2Point calldata publicKey
    )
        public
        view
        returns (bool)
    {
        SkaleVerifier sv;
        return sv.verify(signature, hash, counter, hashA, hashB, publicKey);
    }
}
