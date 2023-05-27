package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "errors"
    kilic "github.com/kilic/bls12-381"
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

type OpBLS_PrivateToPublic struct {
    Modifier ByteSlice
    Priv string
}

type OpBLS_PrivateToPublic_G2 struct {
    Modifier ByteSlice
    Priv string
}

type OpBLS_IsG1OnCurve struct {
    Modifier ByteSlice
    CurveType uint64
    G1_x string
    G1_y string
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

type OpBLS_IsG2OnCurve struct {
    Modifier ByteSlice
    CurveType uint64
    G2_x string
    G2_y string
    G2_v string
    G2_w string
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

//export kilic_bls12_381_Cryptofuzz_GetResult
func kilic_bls12_381_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

func unmarshal(in []byte, op interface{}) {
    err := json.Unmarshal(in, &op)
    if err != nil {
        panic("Cannot unmarshal JSON, which is expected to be well-formed")
    }
}

func loadG1(x, y string) (*kilic.PointG1, error) {
    xbn := decodeBignum(x)
    ybn := decodeBignum(y)

    if xbn.BitLen() > 384 || ybn.BitLen() > 384 {
        return nil, errors.New("")
    }

    result := make([]byte, 96)

    xBytes := make([]byte, 48)
    xbn.FillBytes(xBytes)
    copy(result[:48], xBytes)

    yBytes := make([]byte, 48)
    ybn.FillBytes(yBytes)
    copy(result[48:], yBytes)

    g := kilic.NewG1()
    p, err := g.FromBytes(result)
    return p, err
}

func loadG2(v, w, x, y string) (*kilic.PointG2, error) {
    vbn := decodeBignum(v)
    wbn := decodeBignum(w)
    xbn := decodeBignum(x)
    ybn := decodeBignum(y)

    if vbn.BitLen() > 384 || wbn.BitLen() > 384 {
        return nil, errors.New("")
    }
    if xbn.BitLen() > 384 || ybn.BitLen() > 384 {
        return nil, errors.New("")
    }

    result := make([]byte, 192)

    vBytes := make([]byte, 48)
    vbn.FillBytes(vBytes)

    wBytes := make([]byte, 48)
    wbn.FillBytes(wBytes)

    xBytes := make([]byte, 48)
    xbn.FillBytes(xBytes)

    yBytes := make([]byte, 48)
    ybn.FillBytes(yBytes)

    copy(result[0:48], xBytes)
    copy(result[48:96], vBytes)
    copy(result[96:144], yBytes)
    copy(result[144:192], wBytes)

    g := kilic.NewG2()
    p, err := g.FromBytes(result)
    if err == nil {
        if g.IsZero(p) || !g.InCorrectSubgroup(p) {
            return nil, errors.New("")
        }
    }
    return p, err
}

func loadFr(bn string) (*kilic.Fr, error) {
    v := decodeBignum(bn)
    var fr kilic.Fr
    return fr.FromBytes(v.Bytes()), nil
}


//export kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic
func kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic(in []byte) {
    resetResult()

    var op OpBLS_PrivateToPublic
    unmarshal(in, &op)

    priv := decodeBignum(op.Priv)

    g := kilic.NewG1()
    pub := g.One()
    g.MulScalarBig(pub, pub, priv)

    b := g.ToBytes(pub)

    x := new(big.Int)
    y := new(big.Int)

    x.SetBytes(b[0:48])
    y.SetBytes(b[48:96])

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic_G2
func kilic_bls12_381_Cryptofuzz_OpBLS_PrivateToPublic_G2(in []byte) {
    resetResult()

    var op OpBLS_PrivateToPublic_G2
    unmarshal(in, &op)

    priv := decodeBignum(op.Priv)

    g := kilic.NewG2()
    pub := g.One()
    g.MulScalarBig(pub, pub, priv)

    b := g.ToBytes(pub)

    v := new(big.Int)
    w := new(big.Int)
    x := new(big.Int)
    y := new(big.Int)

    v.SetBytes(b[0:48])
    w.SetBytes(b[48:96])
    x.SetBytes(b[96:144])
    y.SetBytes(b[144:192])

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = w.String()
    res[0][1] = y.String()
    res[1][0] = v.String()
    res[1][1] = x.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_IsG1OnCurve
func kilic_bls12_381_Cryptofuzz_OpBLS_IsG1OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG1OnCurve
    unmarshal(in, &op)

    g := kilic.NewG1()

    g1, err := loadG1(op.G1_x, op.G1_y)

    var res bool

    if err != nil {
        res = false
    } else {
        if g.IsZero(g1) || !g.InCorrectSubgroup(g1) {
            res = false
        } else {
            res = true
        }
    }

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G1_Add
func kilic_bls12_381_Cryptofuzz_OpBLS_G1_Add(in []byte) {
    resetResult()

    var op OpBLS_G1_Add
    unmarshal(in, &op)

    g := kilic.NewG1()

    a, err := loadG1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    b, err := loadG1(op.B_x, op.B_y)
    if err != nil {
        return
    }

    g.Add(a, a, b)

    r := g.ToBytes(a)

    x := new(big.Int)
    y := new(big.Int)

    x.SetBytes(r[0:48])
    y.SetBytes(r[48:96])

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G1_Mul
func kilic_bls12_381_Cryptofuzz_OpBLS_G1_Mul(in []byte) {
    resetResult()

    var op OpBLS_G1_Mul
    unmarshal(in, &op)

    g := kilic.NewG1()
    a, err := loadG1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    b := decodeBignum(op.B)

    if b.BitLen() <= 384 && len(op.Modifier) > 0 && op.Modifier[0] & 1 == 0 {
        var bfr kilic.Fr
        b_bytes := make([]byte, 48)
        b.FillBytes(b_bytes)
        bfr.FromBytes(b_bytes)
        g.MulScalar(a, a, &bfr)
    } else {
        g.MulScalarBig(a, a, b)
    }

    r := g.ToBytes(a)

    x := new(big.Int)
    y := new(big.Int)

    x.SetBytes(r[0:48])
    y.SetBytes(r[48:96])

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G1_Neg
func kilic_bls12_381_Cryptofuzz_OpBLS_G1_Neg(in []byte) {
    resetResult()

    var op OpBLS_G1_Neg
    unmarshal(in, &op)

    g := kilic.NewG1()
    a, err := loadG1(op.A_x, op.A_y)
    if err != nil {
        return
    }

    g.Neg(a, a)

    r := g.ToBytes(a)

    x := new(big.Int)
    y := new(big.Int)

    x.SetBytes(r[0:48])
    y.SetBytes(r[48:96])

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_IsG2OnCurve
func kilic_bls12_381_Cryptofuzz_OpBLS_IsG2OnCurve(in []byte) {
    resetResult()

    var op OpBLS_IsG2OnCurve
    unmarshal(in, &op)

    _, err := loadG2(op.G2_v, op.G2_w, op.G2_x, op.G2_y)

    var res bool

    if err == nil {
        res = true
    } else {
        res = false
    }

    r2, err := json.Marshal(&res)

    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G2_Add
func kilic_bls12_381_Cryptofuzz_OpBLS_G2_Add(in []byte) {
    resetResult()

    var op OpBLS_G2_Add
    unmarshal(in, &op)

    g := kilic.NewG2()

    a, err := loadG2(op.A_v, op.A_w, op.A_x, op.A_y)
    if err != nil {
        return
    }

    b, err := loadG2(op.B_v, op.B_w, op.B_x, op.B_y)
    if err != nil {
        return
    }

    g.Add(a, a, b)

    r := g.ToBytes(a)

    v := new(big.Int)
    w := new(big.Int)
    x := new(big.Int)
    y := new(big.Int)

    v.SetBytes(r[0:48])
    w.SetBytes(r[48:96])
    x.SetBytes(r[96:144])
    y.SetBytes(r[144:192])

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = w.String()
    res[0][1] = y.String()
    res[1][0] = v.String()
    res[1][1] = x.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G2_Mul
func kilic_bls12_381_Cryptofuzz_OpBLS_G2_Mul(in []byte) {
    resetResult()

    var op OpBLS_G2_Mul
    unmarshal(in, &op)

    g := kilic.NewG2()
    a, err := loadG2(op.A_v, op.A_w, op.A_x, op.A_y)
    if err != nil {
        return
    }

    b := decodeBignum(op.B)

    if b.BitLen() <= 384 && len(op.Modifier) > 0 && op.Modifier[0] & 1 == 0 {
        var bfr kilic.Fr
        b_bytes := make([]byte, 48)
        b.FillBytes(b_bytes)
        bfr.FromBytes(b_bytes)
        g.MulScalar(a, a, &bfr)
    } else {
        g.MulScalarBig(a, a, b)
    }

    r := g.ToBytes(a)

    v := new(big.Int)
    w := new(big.Int)
    x := new(big.Int)
    y := new(big.Int)

    v.SetBytes(r[0:48])
    w.SetBytes(r[48:96])
    x.SetBytes(r[96:144])
    y.SetBytes(r[144:192])

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = w.String()
    res[0][1] = y.String()
    res[1][0] = v.String()
    res[1][1] = x.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_G2_Neg
func kilic_bls12_381_Cryptofuzz_OpBLS_G2_Neg(in []byte) {
    resetResult()

    var op OpBLS_G2_Neg
    unmarshal(in, &op)

    g := kilic.NewG2()
    a, err := loadG2(op.A_v, op.A_w, op.A_x, op.A_y)
    if err != nil {
        return
    }

    g.Neg(a, a)

    r := g.ToBytes(a)

    v := new(big.Int)
    w := new(big.Int)
    x := new(big.Int)
    y := new(big.Int)

    v.SetBytes(r[0:48])
    w.SetBytes(r[48:96])
    x.SetBytes(r[96:144])
    y.SetBytes(r[144:192])

    res := make([][]string, 2)
    res[0] = make([]string, 2)
    res[1] = make([]string, 2)

    res[0][0] = w.String()
    res[0][1] = y.String()
    res[1][0] = v.String()
    res[1][1] = x.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBLS_Pairing
func kilic_bls12_381_Cryptofuzz_OpBLS_Pairing(in []byte) {
    resetResult()

    var op OpBLS_Pairing
    unmarshal(in, &op)

    g1, err := loadG1(op.G1_x, op.G1_y)
    if err != nil {
        return
    }

    g2, err := loadG2(op.G2_v, op.G2_w, op.G2_x, op.G2_y)
    if err != nil {
        return
    }

	bls := kilic.NewEngine()
    bls.AddPair(g1, g2)
    e := bls.Result()
    GT := bls.GT()

    r := GT.ToBytes(e)

    res := make([]string, 12)

    for i := 0; i < 12; i++ {
        bn := new(big.Int)
        bn.SetBytes(r[i*48:i*48+48])
        res[11-i] = bn.String()
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export kilic_bls12_381_Cryptofuzz_OpBignumCalc_Fr
func kilic_bls12_381_Cryptofuzz_OpBignumCalc_Fr(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn0, err := loadFr(op.BN0)
    if err != nil {
        return
    }

    bn1, err := loadFr(op.BN1)
    if err != nil {
        return
    }

    var r kilic.Fr

    if false {
    } else if isAdd(op.CalcOp) {
        r.Add(bn0, bn1)
    } else if isSub(op.CalcOp) {
        r.Sub(bn0, bn1)
    } else if isMul(op.CalcOp) {
        r.Mul(bn0, bn1)
    } else if isInvMod(op.CalcOp) {
        r.Inverse(bn0)
    } else if isSqr(op.CalcOp) {
        r.Square(bn0)
    } else if isNot(op.CalcOp) {
        r.Neg(bn0)
    } else if isIsEq(op.CalcOp) {
        if bn0.Equal(bn1) {
            r.One()
        } else {
            r.Zero()
        }
    }

    rr := new(big.Int)
    rr.SetBytes(r.ToBytes())
    res := rr.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
