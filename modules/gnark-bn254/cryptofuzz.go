package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fp"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    "strconv"
)

import "C"

type ByteSlice []byte
type Type uint64

type SliceOpt struct {
    slice ByteSlice
    opt byte
}

func (t *Type) UnmarshalJSON(in []byte) error {
    res, err := strconv.ParseUint(string(in[1:len(in)-1]), 10, 64)
    *t = Type(res)
    return err
}

func (b *ByteSlice) MarshalJSON() ([]byte, error) {
    var buffer bytes.Buffer
    buffer.WriteString("\"")
    buffer.WriteString(hex.EncodeToString(*b))
    buffer.WriteString("\"")
    return buffer.Bytes(), nil
}

func (b *ByteSlice) UnmarshalJSON(in []byte) error {
    res, err := hex.DecodeString(string(in[1:len(in)-1]))
    *b = res
    return err
}

type OpBLS_G1_Add struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    B_x string
    B_y string
}

type OpBLS_G1_Mul struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    B string
}

type OpBLS_G1_Neg struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    B string
}

type OpBLS_G2_Add struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    A_v string
    A_w string
    B_x string
    B_y string
    B_v string
    B_w string
}

type OpBLS_G2_Mul struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    A_v string
    A_w string
    B string
}

type OpBLS_G2_Neg struct {
    Modifier ByteSlice
    CurveType uint64
    A_x string
    A_y string
    A_v string
    A_w string
}

type OpBignumCalc struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 string
    BN1 string
    BN2 string
    BN3 string
}

var result []byte

func resetResult() {
    result = []byte{}
}

func setResult(r ByteSlice) {
    r2, err := json.Marshal(&r)
    if err != nil {
        panic("Cannot marshal to JSON")
    }
    result = r2
}

//export Gnark_bn254_Cryptofuzz_GetResult
func Gnark_bn254_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

func unmarshal(in []byte, op interface{}) {
    err := json.Unmarshal(in, &op)
    if err != nil {
        panic("Cannot unmarshal JSON, which is expected to be well-formed")
    }
}

func decodeBignum(s string) *big.Int {
    if s == "" {
        s = "0"
    }

    bn, ok := new(big.Int).SetString(s, 10)
    if ok == false {
        panic("Cannot decode bignum")
    }
    return bn
}

//export Gnark_bn254_BLS_G1_Add
func Gnark_bn254_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    a_jac := new(bn254.G1Jac).FromAffine(a)

    b := new(bn254.G1Affine)

    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))

    b_jac := new(bn254.G1Jac).FromAffine(b)

    r := new(bn254.G1Affine).FromJacobian(a_jac.AddAssign(b_jac))

    res := make([]string, 2)
    res[0], res[1] = r.X.String(), r.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_G1_Mul
func Gnark_bn254_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    g1 := new(bn254.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.A_x))
    g1.Y.SetBigInt(decodeBignum(op.A_y))

    g1_jac := new(bn254.G1Jac).FromAffine(g1)

    b := decodeBignum(op.B)

    r := new(bn254.G1Jac)
    r.ScalarMultiplication(g1_jac, b)
    r_affine := new(bn254.G1Affine).FromJacobian(r)

    res := make([]string, 2)
    res[0], res[1] = r_affine.X.String(), r_affine.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_G1_Neg
func Gnark_bn254_BLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    g1 := new(bn254.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.A_x))
    g1.Y.SetBigInt(decodeBignum(op.A_y))

    r := new(bn254.G1Affine).Neg(g1)

    res := make([]string, 2)
    res[0], res[1] = r.X.String(), r.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_G2_Add
func Gnark_bn254_BLS_G2_Add(in []byte) {
    resetResult()

    var op OpBLS_G2_Add
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    a_jac := new(bn254.G2Jac).FromAffine(a)

    b := new(bn254.G2Affine)

    b.X.A1.SetBigInt(decodeBignum(op.B_x))
    b.X.A0.SetBigInt(decodeBignum(op.B_v))
    b.Y.A1.SetBigInt(decodeBignum(op.B_y))
    b.Y.A0.SetBigInt(decodeBignum(op.B_w))

    b_jac := new(bn254.G2Jac).FromAffine(b)

    r := new(bn254.G2Affine).FromJacobian(a_jac.AddAssign(b_jac))

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = r.X.A0.String()
    res[0][1] = r.Y.A0.String()
    res[1][0] = r.X.A1.String()
    res[1][1] = r.Y.A1.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_G2_Mul
func Gnark_bn254_BLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g2 := new(bn254.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.A_x))
    g2.X.A0.SetBigInt(decodeBignum(op.A_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.A_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.A_w))

    g2_jac := new(bn254.G2Jac).FromAffine(g2)

    b := decodeBignum(op.B)

    r := new(bn254.G2Jac)
    r.ScalarMultiplication(g2_jac, b)
    r_affine := new(bn254.G2Affine).FromJacobian(r)

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = r_affine.X.A0.String()
    res[0][1] = r_affine.Y.A0.String()
    res[1][0] = r_affine.X.A1.String()
    res[1][1] = r_affine.Y.A1.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_G2_Neg
func Gnark_bn254_BLS_G2_Neg(in []byte) {
    resetResult()

    var op OpBLS_G2_Neg
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    r := new(bn254.G2Affine).Neg(a)

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = r.X.A0.String()
    res[0][1] = r.Y.A0.String()
    res[1][0] = r.X.A1.String()
    res[1][1] = r.Y.A1.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BignumCalc_Fp
func Gnark_bn254_BignumCalc_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]fp.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string

    success := false

    if false {
    } else if isAdd(op.CalcOp) {
        res = new(fp.Element).Add(&bn[0], &bn[1]).String()
        success = true
    } else if isSub(op.CalcOp) {
        res = new(fp.Element).Sub(&bn[0], &bn[1]).String()
        success = true
    } else if isMul(op.CalcOp) {
        res = new(fp.Element).Mul(&bn[0], &bn[1]).String()
        success = true
    } else if isSqr(op.CalcOp) {
        res = new(fp.Element).Square(&bn[0]).String()
        success = true
    } else if isNeg(op.CalcOp) {
        res = new(fp.Element).Neg(&bn[0]).String()
        success = true
    } else if isInvMod(op.CalcOp) {
        res = new(fp.Element).Inverse(&bn[0]).String()
        success = true
    } else if isExp(op.CalcOp) {
        exp := decodeBignum(op.BN1)
        res = new(fp.Element).Exp(bn[0], exp).String()
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(fp.Element).Sqrt(&bn[0])
        if sqrt != nil {
            res = new(fp.Element).Square(sqrt).String()
        } else {
            res = "0"
        }
        success = true
    }

    if success == false {
        return
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BignumCalc_Fr
func Gnark_bn254_BignumCalc_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]fr.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string

    success := false

    if false {
    } else if isAdd(op.CalcOp) {
        res = new(fr.Element).Add(&bn[0], &bn[1]).String()
        success = true
    } else if isSub(op.CalcOp) {
        res = new(fr.Element).Sub(&bn[0], &bn[1]).String()
        success = true
    } else if isMul(op.CalcOp) {
        res = new(fr.Element).Mul(&bn[0], &bn[1]).String()
        success = true
    } else if isSqr(op.CalcOp) {
        res = new(fr.Element).Square(&bn[0]).String()
        success = true
    } else if isNeg(op.CalcOp) {
        res = new(fr.Element).Neg(&bn[0]).String()
        success = true
    } else if isInvMod(op.CalcOp) {
        res = new(fr.Element).Inverse(&bn[0]).String()
        success = true
    } else if isExp(op.CalcOp) {
        exp := decodeBignum(op.BN1)
        res = new(fr.Element).Exp(bn[0], exp).String()
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(fr.Element).Sqrt(&bn[0])
        if sqrt != nil {
            res = new(fr.Element).Square(sqrt).String()
        } else {
            res = "0"
        }
        success = true
    }

    if success == false {
        return
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
