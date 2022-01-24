package main

import (
    "bytes"
    "strconv"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "github.com/cloudflare/circl/ecc/p384"
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

//export circl_Cryptofuzz_GetResult
func circl_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

//export circl_Cryptofuzz_OpECC_Point_Add
func circl_Cryptofuzz_OpECC_Point_Add(in []byte) {
    resetResult()

    var op OpECC_Point_Add
    unmarshal(in, &op)

    if !issecp384r1(op.CurveType) {
        return
    }

    curve := p384.P384()

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    b_x := decodeBignum(op.B_x)
    b_y := decodeBignum(op.B_y)

    res_x, res_y := curve.Add(a_x, a_y, b_x, b_y)

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    if curve.IsOnCurve(b_x, b_y) == false {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = res_x.String(), res_y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export circl_Cryptofuzz_OpECC_Point_Mul
func circl_Cryptofuzz_OpECC_Point_Mul(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    if !issecp384r1(op.CurveType) {
        return
    }

    curve := p384.P384()

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    b := decodeBignum(op.B)
    /* https://github.com/cloudflare/circl/issues/312 */
    order := decodeBignum("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643")
    if ( b.Cmp(order) >= 0 ) {
        return
    }

    res_x, res_y := curve.ScalarMult(a_x, a_y, b.Bytes())

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = res_x.String(), res_y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export circl_Cryptofuzz_OpECC_Point_Dbl
func circl_Cryptofuzz_OpECC_Point_Dbl(in []byte) {
    resetResult()

    var op OpECC_Point_Dbl
    unmarshal(in, &op)

    if !issecp384r1(op.CurveType) {
        return
    }

    curve := p384.P384()

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    res_x, res_y := curve.Double(a_x, a_y)

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    res := make([]string, 2)
    res[0], res[1] = res_x.String(), res_y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
