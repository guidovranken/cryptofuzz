package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc/bn254/fp"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    gnark_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
    bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
    bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
    google "github.com/ethereum/go-ethereum/crypto/bn256/google"
    cloudflare "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
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

type OpBLS_IsG1OnCurve struct {
    Modifier ByteSlice
    CurveType uint64
    G1_x string
    G1_y string
}

type OpBLS_IsG2OnCurve struct {
    Modifier ByteSlice
    CurveType uint64
    G2_x string
    G2_y string
    G2_v string
    G2_w string
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

type OpBLS_MapToG1 struct {
    Modifier ByteSlice
    CurveType uint64
    U string
    V string
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

//export Gnark_bn254_BLS_IsG1OnCurve
func Gnark_bn254_BLS_IsG1OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG1OnCurve
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.G1_x))
    a.Y.SetBigInt(decodeBignum(op.G1_y))

    var res bool
    if a.X.IsZero() && a.Y.IsZero() {
        res = false
    } else {
        res = a.IsOnCurve() && a.IsInSubGroup()
    }

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BLS_IsG2OnCurve
func Gnark_bn254_BLS_IsG2OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG2OnCurve
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.G2_x))
    a.X.A0.SetBigInt(decodeBignum(op.G2_v))
    a.Y.A1.SetBigInt(decodeBignum(op.G2_y))
    a.Y.A0.SetBigInt(decodeBignum(op.G2_w))

    var res bool
    if a.X.A1.IsZero() && a.X.A0.IsZero() && a.Y.A1.IsZero() && a.Y.A0.IsZero() {
        res = false
    } else {
        res = a.IsOnCurve() && a.IsInSubGroup()
    }

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
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

//export Gnark_bn254_BLS_MapToG1
func Gnark_bn254_BLS_MapToG1(in []byte) {
    resetResult()
    return

    var op OpBLS_MapToG1
    unmarshal(in, &op)

    U := decodeBignum(op.U)
    V := decodeBignum(op.V)

    if U.Cmp(new(big.Int).SetUint64(0)) == 0 {
        return
    }
    if V.Cmp(new(big.Int).SetUint64(0)) == 0 {
        return
    }
    u := new(bls12381_fp.Element).SetBigInt(U)
    v := new(bls12381_fp.Element).SetBigInt(V)

    /* https://github.com/ConsenSys/gnark-crypto/blob/b04e1f3a5349a57e4f61eff9df377d1440acad25/ecc/bls12-381/hash_to_curve.go#L151-L157 */
    Q0 := gnark_bls12381.MapToCurveG1Svdw(*u)
    Q1 := gnark_bls12381.MapToCurveG1Svdw(*v)
    var _Q0, _Q1, _res gnark_bls12381.G1Jac
    _Q0.FromAffine(&Q0)
    _Q1.FromAffine(&Q1)
    _res.Set(&_Q1).AddAssign(&_Q0)
    var r_affine gnark_bls12381.G1Affine
    r_affine.FromJacobian(&_res)

    res := make([]string, 2)
    res[0], res[1] = r_affine.X.String(), r_affine.Y.String()

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

//export Gnark_bn254_BignumCalc_bn254_Fp
func Gnark_bn254_BignumCalc_bn254_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]fp.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string
    var r *fp.Element

    success := false
    skipconv := false

    if false {
    } else if isAdd(op.CalcOp) {
        r = new(fp.Element).Add(&bn[0], &bn[1])
        success = true
    } else if isSub(op.CalcOp) {
        r = new(fp.Element).Sub(&bn[0], &bn[1])
        success = true
    } else if isMul(op.CalcOp) {
        r = new(fp.Element).Mul(&bn[0], &bn[1])
        success = true
    } else if isSqr(op.CalcOp) {
        r = new(fp.Element).Square(&bn[0])
        success = true
    } else if isNeg(op.CalcOp) {
        r = new(fp.Element).Neg(&bn[0])
        success = true
    } else if isInvMod(op.CalcOp) {
        r = new(fp.Element).Inverse(&bn[0])
        success = true
    } else if isExp(op.CalcOp) {
        r = new(fp.Element).Exp(bn[0], decodeBignum(op.BN1))
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(fp.Element).Sqrt(&bn[0])
        if sqrt != nil {
            r = new(fp.Element).Square(sqrt)
        } else {
            r = new(fp.Element).SetUint64(0)
        }
        success = true
    } else if isJacobi(op.CalcOp) {
        legendre := bn[0].Legendre()
        res = strconv.Itoa(legendre)
        success = true
        skipconv = true
    } else if isNumBits(op.CalcOp) {
        bitlen := bn[0].BitLen()
        res = strconv.Itoa(bitlen)
        success = true
        skipconv = true
    } else if isDiv(op.CalcOp) {
        r = new(fp.Element).Div(&bn[0], &bn[1])
        success = true
    } else if isSet(op.CalcOp) {
        r = new(fp.Element).Set(&bn[0])
        success = true
    } else if isIsEq(op.CalcOp) {
        if bn[0].Equal(&bn[1]) {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    } else if isIsZero(op.CalcOp) {
        if bn[0].IsZero() {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    }

    if success == false {
        return
    }

    if skipconv == false {
        var b big.Int
        r.ToBigIntRegular(&b)
        res = b.String()
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BignumCalc_bls12381_Fp
func Gnark_bn254_BignumCalc_bls12381_Fp(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]bls12381_fp.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string
    var r *bls12381_fp.Element

    success := false
    skipconv := false

    if false {
    } else if isAdd(op.CalcOp) {
        r = new(bls12381_fp.Element).Add(&bn[0], &bn[1])
        success = true
    } else if isSub(op.CalcOp) {
        r = new(bls12381_fp.Element).Sub(&bn[0], &bn[1])
        success = true
    } else if isMul(op.CalcOp) {
        r = new(bls12381_fp.Element).Mul(&bn[0], &bn[1])
        success = true
    } else if isSqr(op.CalcOp) {
        r = new(bls12381_fp.Element).Square(&bn[0])
        success = true
    } else if isNeg(op.CalcOp) {
        r = new(bls12381_fp.Element).Neg(&bn[0])
        success = true
    } else if isInvMod(op.CalcOp) {
        r = new(bls12381_fp.Element).Inverse(&bn[0])
        success = true
    } else if isExp(op.CalcOp) {
        r = new(bls12381_fp.Element).Exp(bn[0], decodeBignum(op.BN1))
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(bls12381_fp.Element).Sqrt(&bn[0])
        if sqrt != nil {
            r = new(bls12381_fp.Element).Square(sqrt)
        } else {
            r = new(bls12381_fp.Element).SetUint64(0)
        }
        success = true
    } else if isJacobi(op.CalcOp) {
        legendre := bn[0].Legendre()
        res = strconv.Itoa(legendre)
        success = true
        skipconv = true
    } else if isNumBits(op.CalcOp) {
        bitlen := bn[0].BitLen()
        res = strconv.Itoa(bitlen)
        success = true
        skipconv = true
    } else if isDiv(op.CalcOp) {
        r = new(bls12381_fp.Element).Div(&bn[0], &bn[1])
        success = true
    } else if isSet(op.CalcOp) {
        r = new(bls12381_fp.Element).Set(&bn[0])
        success = true
    } else if isIsEq(op.CalcOp) {
        if bn[0].Equal(&bn[1]) {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    } else if isIsZero(op.CalcOp) {
        if bn[0].IsZero() {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    }

    if success == false {
        return
    }

    if skipconv == false {
        var b big.Int
        r.ToBigIntRegular(&b)
        res = b.String()
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BignumCalc_bn254_Fr
func Gnark_bn254_BignumCalc_bn254_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]fr.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string
    var r *fr.Element

    success := false
    skipconv := false

    if false {
    } else if isAdd(op.CalcOp) {
        r = new(fr.Element).Add(&bn[0], &bn[1])
        success = true
    } else if isSub(op.CalcOp) {
        r = new(fr.Element).Sub(&bn[0], &bn[1])
        success = true
    } else if isMul(op.CalcOp) {
        r = new(fr.Element).Mul(&bn[0], &bn[1])
        success = true
    } else if isSqr(op.CalcOp) {
        r = new(fr.Element).Square(&bn[0])
        success = true
    } else if isNeg(op.CalcOp) {
        r = new(fr.Element).Neg(&bn[0])
        success = true
    } else if isInvMod(op.CalcOp) {
        r = new(fr.Element).Inverse(&bn[0])
        success = true
    } else if isExp(op.CalcOp) {
        r = new(fr.Element).Exp(bn[0], decodeBignum(op.BN1))
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(fr.Element).Sqrt(&bn[0])
        if sqrt != nil {
            r = new(fr.Element).Square(sqrt)
        } else {
            r = new(fr.Element).SetUint64(0)
        }
        success = true
    } else if isJacobi(op.CalcOp) {
        legendre := bn[0].Legendre()
        res = strconv.Itoa(legendre)
        success = true
        skipconv = true
    } else if isNumBits(op.CalcOp) {
        bitlen := bn[0].BitLen()
        res = strconv.Itoa(bitlen)
        success = true
        skipconv = true
    } else if isDiv(op.CalcOp) {
        r = new(fr.Element).Div(&bn[0], &bn[1])
        success = true
    } else if isSet(op.CalcOp) {
        r = new(fr.Element).Set(&bn[0])
        success = true
    } else if isIsEq(op.CalcOp) {
        if bn[0].Equal(&bn[1]) {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    } else if isIsZero(op.CalcOp) {
        if bn[0].IsZero() {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    }

    if success == false {
        return
    }

    if skipconv == false {
        var b big.Int
        r.ToBigIntRegular(&b)
        res = b.String()
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Gnark_bn254_BignumCalc_bls12381_Fr
func Gnark_bn254_BignumCalc_bls12381_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]bls12381_fr.Element, 2)
    bn[0].SetBigInt(decodeBignum(op.BN0))
    bn[1].SetBigInt(decodeBignum(op.BN1))

    var res string
    var r *bls12381_fr.Element

    success := false
    skipconv := false

    if false {
    } else if isAdd(op.CalcOp) {
        r = new(bls12381_fr.Element).Add(&bn[0], &bn[1])
        success = true
    } else if isSub(op.CalcOp) {
        r = new(bls12381_fr.Element).Sub(&bn[0], &bn[1])
        success = true
    } else if isMul(op.CalcOp) {
        r = new(bls12381_fr.Element).Mul(&bn[0], &bn[1])
        success = true
    } else if isSqr(op.CalcOp) {
        r = new(bls12381_fr.Element).Square(&bn[0])
        success = true
    } else if isNeg(op.CalcOp) {
        r = new(bls12381_fr.Element).Neg(&bn[0])
        success = true
    } else if isInvMod(op.CalcOp) {
        r = new(bls12381_fr.Element).Inverse(&bn[0])
        success = true
    } else if isExp(op.CalcOp) {
        r = new(bls12381_fr.Element).Exp(bn[0], decodeBignum(op.BN1))
        success = true
    } else if isSqrt(op.CalcOp) {
        sqrt := new(bls12381_fr.Element).Sqrt(&bn[0])
        if sqrt != nil {
            r = new(bls12381_fr.Element).Square(sqrt)
        } else {
            r = new(bls12381_fr.Element).SetUint64(0)
        }
        success = true
    } else if isJacobi(op.CalcOp) {
        legendre := bn[0].Legendre()
        res = strconv.Itoa(legendre)
        success = true
        skipconv = true
    } else if isNumBits(op.CalcOp) {
        bitlen := bn[0].BitLen()
        res = strconv.Itoa(bitlen)
        success = true
        skipconv = true
    } else if isDiv(op.CalcOp) {
        r = new(bls12381_fr.Element).Div(&bn[0], &bn[1])
        success = true
    } else if isSet(op.CalcOp) {
        r = new(bls12381_fr.Element).Set(&bn[0])
        success = true
    } else if isIsEq(op.CalcOp) {
        if bn[0].Equal(&bn[1]) {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    } else if isIsZero(op.CalcOp) {
        if bn[0].IsZero() {
            res = "1"
        } else {
            res = "0"
        }
        success = true
        skipconv = true
    }

    if success == false {
        return
    }

    if skipconv == false {
        var b big.Int
        r.ToBigIntRegular(&b)
        res = b.String()
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Cloudflare_bn256_Cryptofuzz_GetResult
func Cloudflare_bn256_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

//export Cloudflare_bn256_BLS_G1_Add
func Cloudflare_bn256_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(cloudflare.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := new(bn254.G1Affine)

    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))

    bg := new(cloudflare.G1)
    if _, err := bg.Unmarshal(b.Marshal()); err != nil {
        return
    }

    rg := new(cloudflare.G1)
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

//export Cloudflare_bn256_BLS_G1_Mul
func Cloudflare_bn256_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(cloudflare.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := decodeBignum(op.B)

    rg := new(cloudflare.G1)
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

//export Cloudflare_bn256_BLS_G1_Neg
func Cloudflare_bn256_BLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    ag := new(cloudflare.G1)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    rg := new(cloudflare.G1)
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

//export Cloudflare_bn256_BLS_G2_Add
func Cloudflare_bn256_BLS_G2_Add(in []byte) {
    resetResult()

    var op OpBLS_G2_Add
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    ag := new(cloudflare.G2)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    b := new(bn254.G2Affine)

    b.X.A1.SetBigInt(decodeBignum(op.B_x))
    b.X.A0.SetBigInt(decodeBignum(op.B_v))
    b.Y.A1.SetBigInt(decodeBignum(op.B_y))
    b.Y.A0.SetBigInt(decodeBignum(op.B_w))

    bg := new(cloudflare.G2)
    if _, err := bg.Unmarshal(b.Marshal()); err != nil {
        return
    }

    rg := new(cloudflare.G2)
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

//export Cloudflare_bn256_BLS_G2_Mul
func Cloudflare_bn256_BLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g2 := new(bn254.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.A_x))
    g2.X.A0.SetBigInt(decodeBignum(op.A_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.A_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.A_w))

    ag := new(cloudflare.G2)
    if _, err := ag.Unmarshal(g2.Marshal()); err != nil {
        return
    }

    b := decodeBignum(op.B)

    rg := new(cloudflare.G2)
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

//export Cloudflare_bn256_BLS_G2_Neg
func Cloudflare_bn256_BLS_G2_Neg(in []byte) {
    resetResult()

    var op OpBLS_G2_Neg
    unmarshal(in, &op)

    a := new(bn254.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    ag := new(cloudflare.G2)
    if _, err := ag.Unmarshal(a.Marshal()); err != nil {
        return
    }

    rg := new(cloudflare.G2)
    rg.Neg(ag)

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

//export Google_bn256_Cryptofuzz_GetResult
func Google_bn256_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
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
