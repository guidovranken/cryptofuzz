package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    google "github.com/ethereum/go-ethereum/crypto/bn256/google"
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

//export Google_bn256_Cryptofuzz_GetResult
func Google_bn256_Cryptofuzz_GetResult() *C.char {
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

//export Google_bn256_BLS_G1_Add
func Google_bn256_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(google.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := new(bn254.G1Affine)

    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))

    bg := new(google.G1)
    if _, err := bg.Unmarshal(b.Marshal()); err != nil {
        return
    }

    rg := new(google.G1)
    rg.Add(ag, bg)

    r := new(bn254.G1Affine)
    if err := r.Unmarshal(rg.Marshal()); err != nil {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = r.X.String(), r.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Google_bn256_BLS_G1_Mul
func Google_bn256_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(google.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := decodeBignum(op.B)

    rg := new(google.G1)
    rg.ScalarMult(ag, b)

    r := new(bn254.G1Affine)
    if err := r.Unmarshal(rg.Marshal()); err != nil {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = r.X.String(), r.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Google_bn256_BLS_G1_Neg
func Google_bn256_BLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(google.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    rg := new(google.G1)
    rg.Neg(ag)

    r := new(bn254.G1Affine)
    if err := r.Unmarshal(rg.Marshal()); err != nil {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = r.X.String(), r.Y.String()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Google_bn256_BLS_G2_Add
func Google_bn256_BLS_G2_Add(in []byte) {
    resetResult()

    var op OpBLS_G2_Add
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    ag := new(google.G2)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := new(bn254.G2Affine)

    b.X.A1.SetBigInt(decodeBignum(op.B_x))
    b.X.A0.SetBigInt(decodeBignum(op.B_v))
    b.Y.A1.SetBigInt(decodeBignum(op.B_y))
    b.Y.A0.SetBigInt(decodeBignum(op.B_w))

    bg := new(google.G2)
    if _, err := bg.Unmarshal(b.Marshal()); err != nil {
        return
    }

    rg := new(google.G2)
    rg.Add(ag, bg)

    r := new(bn254.G2Affine)
    if err := r.Unmarshal(rg.Marshal()); err != nil {
        return
    }

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

//export Google_bn256_BLS_G2_Mul
func Google_bn256_BLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g2 := new(bn254.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.A_x))
    g2.X.A0.SetBigInt(decodeBignum(op.A_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.A_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.A_w))

    ag := new(google.G2)
    if _, err := ag.Unmarshal(g2.Marshal()); err != nil {
        return
    }

    b := decodeBignum(op.B)

    rg := new(google.G2)
    rg.ScalarMult(ag, b)

    r := new(bn254.G2Affine)
    if err := r.Unmarshal(rg.Marshal()); err != nil {
        return
    }

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

func main() { }
