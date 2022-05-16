package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "strconv"
    "github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
    "github.com/coinbase/kryptology/pkg/core/curves/native/k256"
    "github.com/coinbase/kryptology/pkg/core/curves/native/p256"
)

import "C"

type ByteSlice []byte
type Type uint64

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

type OpECC_Point_Add struct {
    Modifier ByteSlice
    CurveType Type
    A_x string
    A_y string
    B_x string
    B_y string
}

type OpECC_Point_Mul struct {
    Modifier ByteSlice
    CurveType Type
    A_x string
    A_y string
    B string
}

type OpECC_Point_Dbl struct {
    Modifier ByteSlice
    CurveType Type
    A_x string
    A_y string
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

//export Kryptology_Cryptofuzz_GetResult
func Kryptology_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

//export Kryptology_BignumCalc_bls12381_Fr
func Kryptology_BignumCalc_bls12381_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    a := bls12381.Bls12381FqNew().SetBigInt(decodeBignum(op.BN0))
    b := bls12381.Bls12381FqNew().SetBigInt(decodeBignum(op.BN1))

    r := bls12381.Bls12381FqNew()

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(a, b)
    } else if isSub(op.CalcOp) {
        r.Sub(a, b)
    } else if isMul(op.CalcOp) {
        r.Mul(a, b)
    } else if isSqr(op.CalcOp) {
        r.Square(a)
    } else if isSqrt(op.CalcOp) {
        r.Sqrt(a)
        r.Square(r)
    } else if isExp(op.CalcOp) {
        r.Exp(a, b)
    } else if isNeg(op.CalcOp) {
        r.Neg(a)
    } else if isInvMod(op.CalcOp) {
        r.Invert(a)
    } else {
        return
    }

    res := r.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_BignumCalc_bls12381_Fp
func Kryptology_BignumCalc_bls12381_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    /* XXX */
    /* Put: func NewFp() *fp { return new(fp) } */
    /* in fp.go */
    a := bls12381.NewFp().SetBigInt(decodeBignum(op.BN0))
    b := bls12381.NewFp().SetBigInt(decodeBignum(op.BN1))

    r := bls12381.NewFp()

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(a, b)
    } else if isSub(op.CalcOp) {
        r.Sub(a, b)
    } else if isMul(op.CalcOp) {
        r.Mul(a, b)
    } else if isSqr(op.CalcOp) {
        r.Square(a)
    } else if isSqrt(op.CalcOp) {
        r.Sqrt(a)
        r.Square(r)
    } else if isExp(op.CalcOp) {
        r.Exp(a, b)
    } else if isNeg(op.CalcOp) {
        r.Neg(a)
    } else if isInvMod(op.CalcOp) {
        r.Invert(a)
    } else {
        return
    }

    res := r.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_BignumCalc_k256_Fp
func Kryptology_BignumCalc_k256_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    a := k256.K256PointNew().X.SetBigInt(decodeBignum(op.BN0))
    b := k256.K256PointNew().X.SetBigInt(decodeBignum(op.BN1))

    r := k256.K256PointNew().X

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(a, b)
    } else if isSub(op.CalcOp) {
        r.Sub(a, b)
    } else if isMul(op.CalcOp) {
        r.Mul(a, b)
    } else if isSqr(op.CalcOp) {
        r.Square(a)
    } else if isSqrt(op.CalcOp) {
        r.Sqrt(a)
        r.Square(r)
    } else if isExp(op.CalcOp) {
        r.Exp(a, b)
    } else if isNeg(op.CalcOp) {
        r.Neg(a)
    } else if isInvMod(op.CalcOp) {
        r.Invert(a)
    } else {
        return
    }

    res := r.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Add_k256
func Kryptology_ECC_Point_Add_k256(in []byte) {
    resetResult()

    var op OpECC_Point_Add
    unmarshal(in, &op)

    a := k256.K256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    b := k256.K256PointNew()
    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))
    b.Z.SetBigInt(decodeBignum("1"))

    r := k256.K256PointNew()
    r.Add(a, b)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Mul_k256
func Kryptology_ECC_Point_Mul_k256(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    a := k256.K256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    b := k256.K256PointNew().X.SetBigInt(decodeBignum(op.B))

    r := k256.K256PointNew()
    r.Mul(a, b)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Dbl_k256
func Kryptology_ECC_Point_Dbl_k256(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    a := k256.K256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    r := k256.K256PointNew()
    r.Double(a)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Add_p256
func Kryptology_ECC_Point_Add_p256(in []byte) {
    resetResult()

    var op OpECC_Point_Add
    unmarshal(in, &op)

    a := p256.P256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    b := p256.P256PointNew()
    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))
    b.Z.SetBigInt(decodeBignum("1"))

    r := p256.P256PointNew()
    r.Add(a, b)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Mul_p256
func Kryptology_ECC_Point_Mul_p256(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    a := p256.P256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    b := p256.P256PointNew().X.SetBigInt(decodeBignum(op.B))

    r := p256.P256PointNew()
    r.Mul(a, b)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Kryptology_ECC_Point_Dbl_p256
func Kryptology_ECC_Point_Dbl_p256(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    a := p256.P256PointNew()
    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))
    a.Z.SetBigInt(decodeBignum("1"))

    r := p256.P256PointNew()
    r.Double(a)
    r.ToAffine(r)

    res := make([]string, 2)
    res[0], res[1] = r.X.BigInt().String(), r.Y.BigInt().String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
