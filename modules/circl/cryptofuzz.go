package main

import (
    "bytes"
    "strconv"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "github.com/cloudflare/circl/ecc/p384"
    "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/cloudflare/circl/ecc/bls12381/ff"
    "strings"
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

type OpBignumCalc struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 string
    BN1 string
    BN2 string
    BN3 string
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

type OpBLS_IsG1OnCurve struct {
    Modifier ByteSlice
    CurveType uint64
    G1_x string
    G1_y string
}

type OpBLS_Decompress_G1 struct {
    Modifier ByteSlice
    CurveType uint64
    Compressed string
}

type OpBLS_Compress_G1 struct {
    Modifier ByteSlice
    CurveType uint64
    G1_x string
    G1_y string
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

//export circl_bn254_BignumCalc_Fp
func circl_bn254_BignumCalc_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    var bn0 ff.Fp
    var bn1 ff.Fp
    var r ff.Fp

    err := bn0.SetString(strings.TrimLeft(op.BN0, "0"))
    if err != nil {
        return
    }

    err = bn1.SetString(strings.TrimLeft(op.BN1, "0"))
    if err != nil {
        return
    }

    success := false

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(&bn0, &bn1)
        success = true
    } else if isSub(op.CalcOp) {
        r.Sub(&bn0, &bn1)
        success = true
    } else if isMul(op.CalcOp) {
        r.Mul(&bn0, &bn1)
        success = true
    } else if isSqr(op.CalcOp) {
        r.Sqr(&bn0)
        success = true
    } else if isInvMod(op.CalcOp) {
        r.Inv(&bn0)
        success = true
    }

    if success == false {
        return
    }

    b, ok := new(big.Int).SetString(r.String()[2:], 16)
    if ok == false {
        panic("Cannot parse circl output")
    }
    res := b.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export circl_bn254_BignumCalc_Fr
func circl_bn254_BignumCalc_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    var bn0 ff.Scalar
    var bn1 ff.Scalar
    var r ff.Scalar

    err := bn0.SetString(strings.TrimLeft(op.BN0, "0"))
    if err != nil {
        return
    }

    err = bn1.SetString(strings.TrimLeft(op.BN1, "0"))
    if err != nil {
        return
    }

    success := false

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(&bn0, &bn1)
        success = true
    } else if isSub(op.CalcOp) {
        r.Sub(&bn0, &bn1)
        success = true
    } else if isMul(op.CalcOp) {
        r.Mul(&bn0, &bn1)
        success = true
    } else if isSqr(op.CalcOp) {
        r.Sqr(&bn0)
        success = true
    } else if isInvMod(op.CalcOp) {
        r.Inv(&bn0)
        success = true
    }

    if success == false {
        return
    }

    b, ok := new(big.Int).SetString(r.String()[2:], 16)
    if ok == false {
        panic("Cannot parse circl output")
    }
    res := b.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func encode_G1(x, y string) (*bls12381.G1, error) {
    a := new(bls12381.G1)
    var a_x ff.Fp
    var a_y ff.Fp

    err := a_x.SetString(strings.TrimLeft(x, "0"))
    if err != nil {
        return nil, err
    }

    err = a_y.SetString(strings.TrimLeft(y, "0"))
    if err != nil {
        return nil, err
    }

    a_bytes, _ := a_x.MarshalBinary()
    a_y_bytes, _ := a_y.MarshalBinary()
    a_bytes = append(a_bytes, a_y_bytes...)
    a_bytes[0] = a_bytes[0] & 0x1F

    err = a.SetBytes(a_bytes)
    if err != nil {
        return nil, err
    }

    return a, nil
}

func save_G1(r *bls12381.G1) {
    var r_x ff.Fp
    var r_y ff.Fp

    r_bytes := r.Bytes()

    x := (&[ff.FpSize]byte{})[:]
    copy(x, r_bytes)
    x[0] &= 0x1F
    if err := r_x.UnmarshalBinary(x); err != nil {
        panic("Cannot decode result")
    }
    if err := r_y.UnmarshalBinary(r_bytes[ff.FpSize:(2 * ff.FpSize)]); err != nil {
        panic("Cannot decode result")
    }

    x_b, ok := new(big.Int).SetString(r_x.String()[2:], 16)
    if ok == false {
        panic("Cannot parse circl output")
    }

    y_b, ok := new(big.Int).SetString(r_y.String()[2:], 16)
    if ok == false {
        panic("Cannot parse circl output")
    }

    res := make([]string, 2)

    res[0], res[1] = x_b.String(), y_b.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export circl_BLS_G1_Add
func circl_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a, err := encode_G1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    b, err := encode_G1(op.B_x, op.B_y)
    if err != nil {
        return
    }

    r := new(bls12381.G1)
    r.Add(a, b)

    if a.IsOnG1() == false {
        return
    }
    if b.IsOnG1() == false {
        return
    }

    save_G1(r)
}

//export circl_BLS_G1_Mul
func circl_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    a, err := encode_G1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    var b ff.Scalar

    err = b.SetString(strings.TrimLeft(op.B, "0"))
    if err != nil {
        return
    }

    r := new(bls12381.G1)
    r.ScalarMult(&b, a)

    if a.IsOnG1() == false {
        return
    }

    save_G1(r)
}

//export circl_BLS_G1_Neg
func circl_BLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    a, err := encode_G1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    a.Neg()

    save_G1(a)

}

//export circl_BLS_IsG1OnCurve
func circl_BLS_IsG1OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG1OnCurve
    unmarshal(in, &op)

    a, err := encode_G1(op.G1_x, op.G1_y)
    if err != nil {
        return
    }

    res := a.IsOnG1()

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export circl_BLS_Decompress_G1
func circl_BLS_Decompress_G1(in []byte) {
    resetResult()

    var op OpBLS_Decompress_G1
    unmarshal(in, &op)

    compressed := decodeBignum(op.Compressed)

    a := new(bls12381.G1)

    err := a.SetBytes(compressed.Bytes())
    if err != nil {
        return
    }

    save_G1(a)
}

//export circl_BLS_Compress_G1
func circl_BLS_Compress_G1(in []byte) {
    resetResult()

    var op OpBLS_Compress_G1
    unmarshal(in, &op)

    a, err := encode_G1(op.G1_x, op.G1_y)
    if err != nil {
        return
    }

    res := new(big.Int).SetBytes(a.BytesCompressed()).String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
