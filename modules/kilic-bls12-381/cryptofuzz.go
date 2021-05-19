package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    kilic "github.com/kilic/bls12-381"
)

import "C"

type ByteSlice []byte

type SliceOpt struct {
    slice ByteSlice
    opt byte
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

func main() { }
