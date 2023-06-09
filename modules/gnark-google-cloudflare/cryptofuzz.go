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
    bls12381_ecc "github.com/consensys/gnark-crypto/ecc"
    bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
    bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
    gnark_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
    bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
    google "github.com/ethereum/go-ethereum/crypto/bn256/google"
    cloudflare "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
    "strconv"
    "errors"
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

type OpBLS_Pairing struct {
    Modifier ByteSlice
    CurveType uint64
    G1_x string
    G1_y string
    G2_x string
    G2_y string
    G2_v string
    G2_w string
}

type OpBLS_FinalExp struct {
    Modifier ByteSlice
    CurveType uint64
    FP12 [12]string
}

type PointsScalars struct {
    X string
    Y string
    Scalar string
}

type OpBLS_G1_MultiExp struct {
    Modifier ByteSlice
    CurveType uint64
    Points_Scalars []PointsScalars
}

type OpBignumCalc struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 string
    BN1 string
    BN2 string
    BN3 string
}

type OpBignumCalc_Fp2 struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 [2]string
    BN1 [2]string
    BN2 [2]string
    BN3 [2]string
}

type OpBignumCalc_Fp12 struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 [12]string
    BN1 [12]string
    BN2 [12]string
    BN3 [12]string
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

func to32Bytes(s string) ([]byte, error) {
    bn := decodeBignum(s)

    if bn.BitLen() > 256 {
        return nil, errors.New("Too large")
    }

    ret := make([]byte, 32)
    bn.FillBytes(ret)

    return ret, nil
}

func fpToString(v* fp.Element) string {
    var b big.Int
    v.ToBigIntRegular(&b)
    return b.String()
}

func fp12381ToString(v* bls12381_fp.Element) string {
    var b big.Int
    v.ToBigIntRegular(&b)
    return b.String()
}

func fp12377ToString(v* bls12377_fp.Element) string {
    var b big.Int
    v.ToBigIntRegular(&b)
    return b.String()
}

func saveG1(v* bn254.G1Affine) {
    res := make([]string, 2)
    res[0] = fpToString(&v.X)
    res[1] = fpToString(&v.Y)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveG1_bls12381(v* gnark_bls12381.G1Affine) {
    res := make([]string, 2)
    res[0] = fp12381ToString(&v.X)
    res[1] = fp12381ToString(&v.Y)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveG1_bls12377(v* gnark_bls12377.G1Affine) {
    res := make([]string, 2)
    res[0] = fp12377ToString(&v.X)
    res[1] = fp12377ToString(&v.Y)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveG2(v* bn254.G2Affine) {
    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = fpToString(&v.X.A0)
    res[0][1] = fpToString(&v.Y.A0)
    res[1][0] = fpToString(&v.X.A1)
    res[1][1] = fpToString(&v.Y.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveG2_bls12381(v* gnark_bls12381.G2Affine) {
    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = fp12381ToString(&v.X.A0)
    res[0][1] = fp12381ToString(&v.Y.A0)
    res[1][0] = fp12381ToString(&v.X.A1)
    res[1][1] = fp12381ToString(&v.Y.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveFp2_bls12381(v gnark_bls12381.E2) {
    res := make([]string, 2)
    res[0] = fp12381ToString(&v.A0)
    res[1] = fp12381ToString(&v.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveGT_bls12381(v gnark_bls12381.GT) {
    res := make([]string, 12)
    res[0] = fp12381ToString(&v.C0.B0.A0)
    res[1] = fp12381ToString(&v.C0.B0.A1)
    res[2] = fp12381ToString(&v.C0.B1.A0)
    res[3] = fp12381ToString(&v.C0.B1.A1)
    res[4] = fp12381ToString(&v.C0.B2.A0)
    res[5] = fp12381ToString(&v.C0.B2.A1)
    res[6] = fp12381ToString(&v.C1.B0.A0)
    res[7] = fp12381ToString(&v.C1.B0.A1)
    res[8] = fp12381ToString(&v.C1.B1.A0)
    res[9] = fp12381ToString(&v.C1.B1.A1)
    res[10] = fp12381ToString(&v.C1.B2.A0)
    res[11] = fp12381ToString(&v.C1.B2.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveGT_bn254(v bn254.GT) {
    res := make([]string, 12)
    res[0] = fpToString(&v.C0.B0.A0)
    res[1] = fpToString(&v.C0.B0.A1)
    res[2] = fpToString(&v.C0.B1.A0)
    res[3] = fpToString(&v.C0.B1.A1)
    res[4] = fpToString(&v.C0.B2.A0)
    res[5] = fpToString(&v.C0.B2.A1)
    res[6] = fpToString(&v.C1.B0.A0)
    res[7] = fpToString(&v.C1.B0.A1)
    res[8] = fpToString(&v.C1.B1.A0)
    res[9] = fpToString(&v.C1.B1.A1)
    res[10] = fpToString(&v.C1.B2.A0)
    res[11] = fpToString(&v.C1.B2.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func saveG2_bls12377(v* gnark_bls12377.G2Affine) {
    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = fp12377ToString(&v.X.A0)
    res[0][1] = fp12377ToString(&v.Y.A0)
    res[1][0] = fp12377ToString(&v.X.A1)
    res[1][1] = fp12377ToString(&v.Y.A1)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func Gnark_bn256_IsG1OnCurve(v* bn254.G1Affine) bool {
    if v.X.IsZero() && v.Y.IsZero() {
        return false
    } else {
        return v.IsOnCurve() && v.IsInSubGroup()
    }
}

//export Gnark_bn254_BLS_IsG1OnCurve
func Gnark_bn254_BLS_IsG1OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG1OnCurve
    unmarshal(in, &op)

    a := new(bn254.G1Affine)

    a.X.SetBigInt(decodeBignum(op.G1_x))
    a.Y.SetBigInt(decodeBignum(op.G1_y))

    res := Gnark_bn256_IsG1OnCurve(a)

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func Gnark_bls12_381_IsG1OnCurve(v* gnark_bls12381.G1Affine) bool {
    if v.X.IsZero() && v.Y.IsZero() {
        return false
    } else {
        return v.IsOnCurve() && v.IsInSubGroup()
    }
}

func Gnark_bls12_381_IsG2OnCurve(v* gnark_bls12381.G2Affine) bool {
    if v.X.A0.IsZero() && v.X.A1.IsZero() && v.Y.A0.IsZero() && v.Y.A1.IsZero() {
        return false
    } else {
        return v.IsOnCurve() && v.IsInSubGroup()
    }
}

func Gnark_bls12_377_IsG1OnCurve(v* gnark_bls12377.G1Affine) bool {
    if v.X.IsZero() && v.Y.IsZero() {
        return false
    } else {
        return v.IsOnCurve() && v.IsInSubGroup()
    }
}

//export Gnark_bls12_381_BLS_IsG1OnCurve
func Gnark_bls12_381_BLS_IsG1OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG1OnCurve
    unmarshal(in, &op)

    a := new(gnark_bls12381.G1Affine)

    a.X.SetBigInt(decodeBignum(op.G1_x))
    a.Y.SetBigInt(decodeBignum(op.G1_y))

    res := Gnark_bls12_381_IsG1OnCurve(a)

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

//export Gnark_bls12_381_BLS_IsG2OnCurve
func Gnark_bls12_381_BLS_IsG2OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG2OnCurve
    unmarshal(in, &op)

    a := new(gnark_bls12381.G2Affine)

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

    saveG1(r)
}

//export Gnark_bls12_381_BLS_G1_Add
func Gnark_bls12_381_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a := new(gnark_bls12381.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    a_jac := new(gnark_bls12381.G1Jac).FromAffine(a)

    b := new(gnark_bls12381.G1Affine)

    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))

    b_jac := new(gnark_bls12381.G1Jac).FromAffine(b)

    r := new(gnark_bls12381.G1Affine).FromJacobian(a_jac.AddAssign(b_jac))

    if !Gnark_bls12_381_IsG1OnCurve(a) {
        //return
    }
    if !Gnark_bls12_381_IsG1OnCurve(b) {
        //return
    }

    saveG1_bls12381(r)
}

//export Gnark_bls12_377_BLS_G1_Add
func Gnark_bls12_377_BLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    a := new(gnark_bls12377.G1Affine)

    a.X.SetBigInt(decodeBignum(op.A_x))
    a.Y.SetBigInt(decodeBignum(op.A_y))

    a_jac := new(gnark_bls12377.G1Jac).FromAffine(a)

    b := new(gnark_bls12377.G1Affine)

    b.X.SetBigInt(decodeBignum(op.B_x))
    b.Y.SetBigInt(decodeBignum(op.B_y))

    b_jac := new(gnark_bls12377.G1Jac).FromAffine(b)

    r := new(gnark_bls12377.G1Affine).FromJacobian(a_jac.AddAssign(b_jac))

    if !Gnark_bls12_377_IsG1OnCurve(a) {
        return
    }
    if !Gnark_bls12_377_IsG1OnCurve(b) {
        return
    }

    saveG1_bls12377(r)
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

    saveG1(r_affine)
}

//export Gnark_bls12_381_BLS_G1_Mul
func Gnark_bls12_381_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    g1 := new(gnark_bls12381.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.A_x))
    g1.Y.SetBigInt(decodeBignum(op.A_y))

    g1_jac := new(gnark_bls12381.G1Jac).FromAffine(g1)

    b := decodeBignum(op.B)

    r := new(gnark_bls12381.G1Jac)
    r.ScalarMultiplication(g1_jac, b)
    r_affine := new(gnark_bls12381.G1Affine).FromJacobian(r)

    if !Gnark_bls12_381_IsG1OnCurve(g1) {
        return
    }

    saveG1_bls12381(r_affine)
}

//export Gnark_bls12_377_BLS_G1_Mul
func Gnark_bls12_377_BLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    g1 := new(gnark_bls12377.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.A_x))
    g1.Y.SetBigInt(decodeBignum(op.A_y))

    if !Gnark_bls12_377_IsG1OnCurve(g1) {
        return
    }

    g1_jac := new(gnark_bls12377.G1Jac).FromAffine(g1)

    b := decodeBignum(op.B)

    if b.BitLen() == 0 {
        return
    }

    r := new(gnark_bls12377.G1Jac)
    r.ScalarMultiplication(g1_jac, b)
    r_affine := new(gnark_bls12377.G1Affine).FromJacobian(r)

    saveG1_bls12377(r_affine)
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

    saveG1(r)
}

//export Gnark_bls12_381_BLS_G1_Neg
func Gnark_bls12_381_BLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    g1 := new(gnark_bls12381.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.A_x))
    g1.Y.SetBigInt(decodeBignum(op.A_y))

    r := new(gnark_bls12381.G1Affine).Neg(g1)

    saveG1_bls12381(r)
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

    saveG2(r)
}

//export Gnark_bls12_381_BLS_G2_Add
func Gnark_bls12_381_BLS_G2_Add(in []byte) {
    resetResult()

    var op OpBLS_G2_Add
    unmarshal(in, &op)

    a := new(gnark_bls12381.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    a_jac := new(gnark_bls12381.G2Jac).FromAffine(a)

    b := new(gnark_bls12381.G2Affine)

    b.X.A1.SetBigInt(decodeBignum(op.B_x))
    b.X.A0.SetBigInt(decodeBignum(op.B_v))
    b.Y.A1.SetBigInt(decodeBignum(op.B_y))
    b.Y.A0.SetBigInt(decodeBignum(op.B_w))

    b_jac := new(gnark_bls12381.G2Jac).FromAffine(b)

    r := new(gnark_bls12381.G2Affine).FromJacobian(a_jac.AddAssign(b_jac))

    saveG2_bls12381(r)
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

    saveG2(r_affine)
}

//export Gnark_bls12_381_BLS_G2_Mul
func Gnark_bls12_381_BLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g2 := new(gnark_bls12381.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.A_x))
    g2.X.A0.SetBigInt(decodeBignum(op.A_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.A_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.A_w))

    g2_jac := new(gnark_bls12381.G2Jac).FromAffine(g2)

    b := decodeBignum(op.B)

    r := new(gnark_bls12381.G2Jac)
    r.ScalarMultiplication(g2_jac, b)
    r_affine := new(gnark_bls12381.G2Affine).FromJacobian(r)

    if !g2.IsOnCurve() || !g2.IsInSubGroup() {
        return
    }

    saveG2_bls12381(r_affine)
}

//export Gnark_bls12_377_BLS_G2_Mul
func Gnark_bls12_377_BLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g2 := new(gnark_bls12377.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.A_x))
    g2.X.A0.SetBigInt(decodeBignum(op.A_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.A_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.A_w))

    g2_jac := new(gnark_bls12377.G2Jac).FromAffine(g2)

    b := decodeBignum(op.B)

    r := new(gnark_bls12377.G2Jac)
    r.ScalarMultiplication(g2_jac, b)
    r_affine := new(gnark_bls12377.G2Affine).FromJacobian(r)

    if !g2.IsOnCurve() || !g2.IsInSubGroup() {
        return
    }

    saveG2_bls12377(r_affine)
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

    saveG2(r)
}

//export Gnark_bls12_381_BLS_G2_Neg
func Gnark_bls12_381_BLS_G2_Neg(in []byte) {
    resetResult()

    var op OpBLS_G2_Neg
    unmarshal(in, &op)

    a := new(gnark_bls12381.G2Affine)

    a.X.A1.SetBigInt(decodeBignum(op.A_x))
    a.X.A0.SetBigInt(decodeBignum(op.A_v))
    a.Y.A1.SetBigInt(decodeBignum(op.A_y))
    a.Y.A0.SetBigInt(decodeBignum(op.A_w))

    r := new(gnark_bls12381.G2Affine).Neg(a)

    saveG2_bls12381(r)
}

//export Gnark_bls12_381_BLS_Pairing
func Gnark_bls12_381_BLS_Pairing(in []byte) {
    resetResult()

    var op OpBLS_Pairing
    unmarshal(in, &op)

    g1 := new(gnark_bls12381.G1Affine)

    g1.X.SetBigInt(decodeBignum(op.G1_x))
    g1.Y.SetBigInt(decodeBignum(op.G1_y))

    g2 := new(gnark_bls12381.G2Affine)

    g2.X.A1.SetBigInt(decodeBignum(op.G2_x))
    g2.X.A0.SetBigInt(decodeBignum(op.G2_v))
    g2.Y.A1.SetBigInt(decodeBignum(op.G2_y))
    g2.Y.A0.SetBigInt(decodeBignum(op.G2_w))

    r, _ := gnark_bls12381.Pair(
        []gnark_bls12381.G1Affine{*g1},
        []gnark_bls12381.G2Affine{*g2})

    if !Gnark_bls12_381_IsG1OnCurve(g1) {
        return
    }
    if !Gnark_bls12_381_IsG2OnCurve(g2) {
        return
    }

    saveGT_bls12381(r)
}

//export Gnark_bls12_381_BLS_FinalExp
func Gnark_bls12_381_BLS_FinalExp(in []byte) {
    resetResult()

    var op OpBLS_FinalExp
    unmarshal(in, &op)

    fp12 := gnark_bls12381.E12{}
    fp12.C0.B0.A0.SetBigInt(decodeBignum(op.FP12[0]))
    fp12.C0.B0.A1.SetBigInt(decodeBignum(op.FP12[1]))
    fp12.C0.B1.A0.SetBigInt(decodeBignum(op.FP12[2]))
    fp12.C0.B1.A1.SetBigInt(decodeBignum(op.FP12[3]))
    fp12.C0.B2.A0.SetBigInt(decodeBignum(op.FP12[4]))
    fp12.C0.B2.A1.SetBigInt(decodeBignum(op.FP12[5]))
    fp12.C1.B0.A0.SetBigInt(decodeBignum(op.FP12[6]))
    fp12.C1.B0.A1.SetBigInt(decodeBignum(op.FP12[7]))
    fp12.C1.B1.A0.SetBigInt(decodeBignum(op.FP12[8]))
    fp12.C1.B1.A1.SetBigInt(decodeBignum(op.FP12[9]))
    fp12.C1.B2.A0.SetBigInt(decodeBignum(op.FP12[10]))
    fp12.C1.B2.A1.SetBigInt(decodeBignum(op.FP12[11]))

    r := gnark_bls12381.FinalExponentiation(&fp12)

    saveGT_bls12381(r)
}

//export Gnark_bls12_381_BLS_G1_MultiExp
func Gnark_bls12_381_BLS_G1_MultiExp(in []byte) {
    resetResult()

    var op OpBLS_G1_MultiExp
    unmarshal(in, &op)

    N := len(op.Points_Scalars)
    points := make([]gnark_bls12381.G1Affine, N)
    scalars := make([]bls12381_fr.Element, N)
    for i := 0; i < N; i++ {
        points[i].X.SetBigInt(decodeBignum(op.Points_Scalars[i].X))
        points[i].Y.SetBigInt(decodeBignum(op.Points_Scalars[i].Y))
        scalars[i].SetBigInt(decodeBignum(op.Points_Scalars[i].Scalar))
    }

    var x gnark_bls12381.G1Affine
    nbtasks := 1
    if len(op.Modifier) > 0 {
        nbtasks = int(op.Modifier[0])
    }
    r, err := x.MultiExp(points[:], scalars[:], bls12381_ecc.MultiExpConfig{NbTasks: nbtasks})

    if err != nil {
        return
    }

    saveG1_bls12381(r)
}

//export Gnark_bn254_BLS_FinalExp
func Gnark_bn254_BLS_FinalExp(in []byte) {
    resetResult()

    var op OpBLS_FinalExp
    unmarshal(in, &op)

    fp12 := bn254.E12{}
    fp12.C0.B0.A0.SetBigInt(decodeBignum(op.FP12[0]))
    fp12.C0.B0.A1.SetBigInt(decodeBignum(op.FP12[1]))
    fp12.C0.B1.A0.SetBigInt(decodeBignum(op.FP12[2]))
    fp12.C0.B1.A1.SetBigInt(decodeBignum(op.FP12[3]))
    fp12.C0.B2.A0.SetBigInt(decodeBignum(op.FP12[4]))
    fp12.C0.B2.A1.SetBigInt(decodeBignum(op.FP12[5]))
    fp12.C1.B0.A0.SetBigInt(decodeBignum(op.FP12[6]))
    fp12.C1.B0.A1.SetBigInt(decodeBignum(op.FP12[7]))
    fp12.C1.B1.A0.SetBigInt(decodeBignum(op.FP12[8]))
    fp12.C1.B1.A1.SetBigInt(decodeBignum(op.FP12[9]))
    fp12.C1.B2.A0.SetBigInt(decodeBignum(op.FP12[10]))
    fp12.C1.B2.A1.SetBigInt(decodeBignum(op.FP12[11]))

    r := bn254.FinalExponentiation(&fp12)

    saveGT_bn254(r)
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

//export Gnark_bn254_BignumCalc_bls2381_Fp2
func Gnark_bn254_BignumCalc_bls2381_Fp2(in []byte) {
    resetResult()

    var op OpBignumCalc_Fp2
    unmarshal(in, &op)

    bn0 := gnark_bls12381.E2{}
    bn0.A0.SetBigInt(decodeBignum(op.BN0[0]))
    bn0.A1.SetBigInt(decodeBignum(op.BN0[1]))

    bn1 := gnark_bls12381.E2{}
    bn1.A0.SetBigInt(decodeBignum(op.BN1[0]))
    bn1.A1.SetBigInt(decodeBignum(op.BN1[1]))


    if false {
    } else if isAdd(op.CalcOp) {
        bn0.Add(&bn0, &bn1)
    } else if isSub(op.CalcOp) {
        bn0.Sub(&bn0, &bn1)
    } else if isMul(op.CalcOp) {
        bn0.Mul(&bn0, &bn1)
    } else if isSqr(op.CalcOp) {
        bn0.Square(&bn0)
    } else if isInvMod(op.CalcOp) {
        bn0.Inverse(&bn0)
    } else if isConjugate(op.CalcOp) {
        bn0.Conjugate(&bn0)
    } else if isSqrt(op.CalcOp) {
        if bn0.Legendre() == 1 {
            bn0.Sqrt(&bn0)
            bn0.Square(&bn0)
        } else {
            bn0.SetZero()
        }
    } else {
        return
    }

    saveFp2_bls12381(bn0)
}

//export Gnark_bn254_BignumCalc_bls12381_Fp12
func Gnark_bn254_BignumCalc_bls12381_Fp12(in []byte) {
    resetResult()

    var op OpBignumCalc_Fp12
    unmarshal(in, &op)

    bn0 := gnark_bls12381.E12{}
    bn0.C0.B0.A0.SetBigInt(decodeBignum(op.BN0[0]))
    bn0.C0.B0.A1.SetBigInt(decodeBignum(op.BN0[1]))
    bn0.C0.B1.A0.SetBigInt(decodeBignum(op.BN0[2]))
    bn0.C0.B1.A1.SetBigInt(decodeBignum(op.BN0[3]))
    bn0.C0.B2.A0.SetBigInt(decodeBignum(op.BN0[4]))
    bn0.C0.B2.A1.SetBigInt(decodeBignum(op.BN0[5]))
    bn0.C1.B0.A0.SetBigInt(decodeBignum(op.BN0[6]))
    bn0.C1.B0.A1.SetBigInt(decodeBignum(op.BN0[7]))
    bn0.C1.B1.A0.SetBigInt(decodeBignum(op.BN0[8]))
    bn0.C1.B1.A1.SetBigInt(decodeBignum(op.BN0[9]))
    bn0.C1.B2.A0.SetBigInt(decodeBignum(op.BN0[10]))
    bn0.C1.B2.A1.SetBigInt(decodeBignum(op.BN0[11]))

    bn1 := gnark_bls12381.E12{}
    bn1.C0.B0.A0.SetBigInt(decodeBignum(op.BN1[0]))
    bn1.C0.B0.A1.SetBigInt(decodeBignum(op.BN1[1]))
    bn1.C0.B1.A0.SetBigInt(decodeBignum(op.BN1[2]))
    bn1.C0.B1.A1.SetBigInt(decodeBignum(op.BN1[3]))
    bn1.C0.B2.A0.SetBigInt(decodeBignum(op.BN1[4]))
    bn1.C0.B2.A1.SetBigInt(decodeBignum(op.BN1[5]))
    bn1.C1.B0.A0.SetBigInt(decodeBignum(op.BN1[6]))
    bn1.C1.B0.A1.SetBigInt(decodeBignum(op.BN1[7]))
    bn1.C1.B1.A0.SetBigInt(decodeBignum(op.BN1[8]))
    bn1.C1.B1.A1.SetBigInt(decodeBignum(op.BN1[9]))
    bn1.C1.B2.A0.SetBigInt(decodeBignum(op.BN1[10]))
    bn1.C1.B2.A1.SetBigInt(decodeBignum(op.BN1[11]))

    if false {
    } else if isAdd(op.CalcOp) {
        bn0.Add(&bn0, &bn1)
    } else if isSub(op.CalcOp) {
        bn0.Sub(&bn0, &bn1)
    } else if isMul(op.CalcOp) {
        bn0.Mul(&bn0, &bn1)
    } else if isSqr(op.CalcOp) {
        bn0.Square(&bn0)
    } else if isInvMod(op.CalcOp) {
        bn0.Inverse(&bn0)
    } else if isConjugate(op.CalcOp) {
        bn0.Conjugate(&bn0)
    } else if isCyclotomicSqr(op.CalcOp) {
        bn0.CyclotomicSquare(&bn1)
    } else {
        return
    }

    saveGT_bls12381(bn0)
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

    saveG1(r)
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

    saveG1(r)
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

    saveG1(r)
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

    saveG2(r)
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

    saveG2(r)
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

    saveG2(r)
}

func saveGT(v *cloudflare.GT) {
    bytes := v.Marshal()

    res := make([]string, 12)
    for i := 0; i < 12; i++ {
        bn := new(big.Int)
        bn.SetBytes(bytes[i * 32:i * 32 + 32])
        res[11-i] = bn.String()
    }

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Cloudflare_bn256_BLS_FinalExp
func Cloudflare_bn256_BLS_FinalExp(in []byte) {
    resetResult()

    var op OpBLS_FinalExp
    unmarshal(in, &op)

    fp12 := cloudflare.GT{}
    serialized := make([]byte, 0, len(op.FP12) * 32)
    for i := 0; i < 12; i++ {
        bytes, err := to32Bytes(op.FP12[11-i])
        if err != nil {
            return
        }
        serialized = append(serialized, bytes...)
    }

    _, err := fp12.Unmarshal(serialized)
    if err != nil {
        return
    }

    r := fp12.Finalize()
    /* Adjust to match other libraries */
    /* 2*u*(6*u^2 + 3*u + 1) */
	u, _ := new(big.Int).SetString("0x3bec47df15e307c81ea96b02d9d9e38d2e5d4e223ddedaf4", 0)
    r = r.ScalarMult(r, u)
    saveGT(r)
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

    saveG1(r)
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

    saveG1(r)
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

    saveG1(r)
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

    saveG2(r)
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

    saveG2(r)
}

func main() { }
