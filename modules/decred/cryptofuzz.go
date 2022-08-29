package main

import (
    "fmt"
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
	"github.com/decred/dcrd/dcrec/secp256k1"
    "github.com/decred/dcrd/dcrec/secp256k1/ecdsa"
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

type OpECC_PrivateToPublic struct {
    Modifier ByteSlice
    CurveType uint64
    Priv string
}

type OpECDSA_Verify struct {
    Modifier ByteSlice
    CurveType uint64
    DigestType uint64
    Pub_X string
    Pub_Y string
    Cleartext ByteSlice
    Sig_R string
    Sig_S string
}

type OpECDSA_Sign struct {
    Modifier ByteSlice
    CurveType uint64
    DigestType uint64
    Priv string
    Cleartext ByteSlice
}

type ECDSA_Signature struct {
    Pub [2]string `json:"pub"`
    Sig ByteSlice `json:"sig"`
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

//export Decred_Cryptofuzz_GetResult
func Decred_Cryptofuzz_GetResult() *C.char {
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

//export Decred_Cryptofuzz_OpECC_PrivateToPublic
func Decred_Cryptofuzz_OpECC_PrivateToPublic(in []byte) {
    resetResult()

    var op OpECC_PrivateToPublic
    unmarshal(in, &op)

    if !issecp256k1(op.CurveType) {
        return
    }

    privBn := decodeBignum(op.Priv)
    if privBn.Cmp(decodeBignum("115792089237316195423570985008687907852837564279074904382605163141518161494337")) >= 0 {
        return
    }
    privBytes := privBn.Bytes()

    pubKey := secp256k1.PrivKeyFromBytes(privBytes).PubKey().SerializeUncompressed()
    x := new(big.Int)
    x.SetBytes(pubKey[1:33])

    y := new(big.Int)
    y.SetBytes(pubKey[33:65])

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func encodePubkey(X* big.Int, Y* big.Int) ([]byte, error) {
    XBytes := X.Bytes()
    YBytes := Y.Bytes()
    XLen := len(XBytes)
    YLen := len(YBytes)

    if XLen > 32 || YLen > 32 {
        return nil, fmt.Errorf("X or Y too large")
    }

    ret := make([]byte, 0)
    ret = append(ret, 0x04)
    ret = append(ret, make([]byte, 32-XLen)...)
    ret = append(ret, XBytes...)
    ret = append(ret, make([]byte, 32-YLen)...)
    ret = append(ret, YBytes...)

    return ret, nil
}

func encodeSignature(R* big.Int, S* big.Int) ([]byte, error) {
    RBytes := R.Bytes()
    SBytes := S.Bytes()
    RLen := len(RBytes)
    SLen := len(SBytes)

    if RLen > 32 || SLen > 32 {
        return nil, fmt.Errorf("R or S too large")
    }

    RHigh := RLen > 0 && (RBytes[0] & 0x80 == 0x80)
    SHigh := SLen > 0 && (SBytes[0] & 0x80 == 0x80)
    if RHigh == true {
        RLen += 1
    }
    if SHigh == true {
        SLen += 1
    }

    ret := make([]byte, 0)
    ret = append(ret, 0x30)
    ret = append(ret, byte((2 + RLen) + (2 + SLen)))

    ret = append(ret, 0x02)
    ret = append(ret, byte(RLen))
    if RHigh == true {
        ret = append(ret, 0x00)
    }
    ret = append(ret, RBytes...)

    ret = append(ret, 0x02)
    ret = append(ret, byte(SLen))
    if SHigh == true {
        ret = append(ret, 0x00)
    }
    ret = append(ret, SBytes...)

    return ret, nil
}

func secp256k1_Verify(op OpECDSA_Verify) {
    sigR := decodeBignum(op.Sig_R)
    sigS := decodeBignum(op.Sig_S)

    sigDER, err := encodeSignature(sigR, sigS)
    if err != nil {
        return
    }

    X := decodeBignum(op.Pub_X)
    Y := decodeBignum(op.Pub_Y)
    pubEncoded, err := encodePubkey(X, Y)
    if err != nil {
        return
    }

    pub, err := secp256k1.ParsePubKey(pubEncoded)
    if err != nil {
        return
    }

    sig, err := ecdsa.ParseDERSignature(sigDER)
    if err != nil {
        return
    }

    res := sig.Verify(op.Cleartext, pub)

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func secp256k1_Sign(op OpECDSA_Sign) {
    privBn := decodeBignum(op.Priv)
    if privBn.Cmp(decodeBignum("115792089237316195423570985008687907852837564279074904382605163141518161494337")) >= 0 {
        return
    }
    if privBn.Cmp(new(big.Int).SetUint64(0)) == 0 {
        return
    }
    privBytes := privBn.Bytes()

    priv := secp256k1.PrivKeyFromBytes(privBytes)

    pubKey := secp256k1.PrivKeyFromBytes(privBytes).PubKey().SerializeUncompressed()
    x := new(big.Int)
    x.SetBytes(pubKey[1:33])

    y := new(big.Int)
    y.SetBytes(pubKey[33:65])

    sig := ecdsa.Sign(priv, op.Cleartext).Serialize()

    var res ECDSA_Signature
    res.Pub[0] = x.String()
    res.Pub[1] = y.String()
    res.Sig = sig

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Decred_Cryptofuzz_OpECDSA_Verify
func Decred_Cryptofuzz_OpECDSA_Verify(in []byte) {
    resetResult()

    var op OpECDSA_Verify
    unmarshal(in, &op)

    if isNULL(op.DigestType) == false {
        return
    }

    if issecp256k1(op.CurveType) {
        secp256k1_Verify(op)
    }
}

//export Decred_Cryptofuzz_OpECDSA_Sign
func Decred_Cryptofuzz_OpECDSA_Sign(in []byte) {
    resetResult()

    var op OpECDSA_Sign
    unmarshal(in, &op)

    if isNULL(op.DigestType) == false {
        return
    }

    if issecp256k1(op.CurveType) {
        secp256k1_Sign(op)
    }

}

func main() { }
