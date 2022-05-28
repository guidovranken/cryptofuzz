package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "strconv"
    "github.com/holiman/uint256"
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

//export holiman_uint256_Cryptofuzz_GetResult
func holiman_uint256_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
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

func unmarshal(in []byte, op interface{}) {
    err := json.Unmarshal(in, &op)
    if err != nil {
        panic("Cannot unmarshal JSON, which is expected to be well-formed")
    }
}

//export holiman_uint256_Cryptofuzz_OpBignumCalc
func holiman_uint256_Cryptofuzz_OpBignumCalc(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn0 := decodeBignum(op.BN0)
    if bn0.BitLen() > 256 {
        return
    }
    u0 := new(uint256.Int).SetBytes(bn0.Bytes())

    bn1 := decodeBignum(op.BN1)
    if bn1.BitLen() > 256 {
        return
    }
    u1 := new(uint256.Int).SetBytes(bn1.Bytes())

    bn2 := decodeBignum(op.BN2)

    res := new(uint256.Int).SetBytes(bn2.Bytes())

    var mod byte = 0
    if len(op.Modifier) >= 1 {
        mod = op.Modifier[0]
    }

    if false {
    } else if isAdd(op.CalcOp) {
        if mod % 2 == 0 {
            res.Add(u0, u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res.AddUint64(u0, u1.Uint64())
        }
    } else if isSub(op.CalcOp) {
        if mod % 2 == 0 {
            res.Sub(u0, u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res.SubUint64(u0, u1.Uint64())
        }
    } else if isMul(op.CalcOp) {
        res.Mul(u0, u1)
    } else if isDiv(op.CalcOp) {
        if u1.IsZero() {
            return
        }
        res.Div(u0, u1)
    } else if isExp(op.CalcOp) {
        res.Exp(u0, u1)
    } else if isSqrt(op.CalcOp) {
        res.Sqrt(u0)
    } else if isRShift(op.CalcOp) {
        if !u1.IsUint64() {
            return
        }
        res.Rsh(u0, (uint)(u1.Uint64()))
    } else if isLShift(op.CalcOp) {
        if !u1.IsUint64() {
            return
        }
        res.Lsh(u0, (uint)(u1.Uint64()))
    } else if isLShift1(op.CalcOp) {
        res.Lsh(u0, 1)
    } else if isNot(op.CalcOp) {
        res.Neg(u0)
    } else if isAnd(op.CalcOp) {
        res.And(u0, u1)
    } else if isOr(op.CalcOp) {
        res.Or(u0, u1)
    } else if isXor(op.CalcOp) {
        res.Xor(u0, u1)
    } else if isNumBits(op.CalcOp) {
        res.SetUint64((uint64)(u0.BitLen()))
    } else if isIsEq(op.CalcOp) {
        res.Clear()
        if u0.Eq(u1) {
            res.AddUint64(res, 1)
        }
    } else if isIsLt(op.CalcOp) {
        res.Clear()
        if u0.Lt(u1) {
            res.AddUint64(res, 1)
        }
    } else if isIsGt(op.CalcOp) {
        res.Clear()
        if u0.Gt(u1) {
            res.AddUint64(res, 1)
        }
    } else if isIsZero(op.CalcOp) {
        res.Clear()
        if u0.IsZero() {
            res.AddUint64(res, 1)
        }
    } else if isSet(op.CalcOp) {
        if mod % 2 == 0 {
            if !u0.IsUint64() {
                return
            }
            res.SetUint64(u0.Uint64())
        } else {
            res.SetBytes(u0.Bytes())
        }
    } else if isAddMod(op.CalcOp) {
        res.AddMod(u0, u1, res)
    } else if isMulMod(op.CalcOp) {
        res.MulMod(u0, u1, res)
    } else if isSDiv(op.CalcOp) {
        res.SDiv(u0, u1)
    } else {
        return
    }

    resStr := res.ToBig().String()
    r2, err := json.Marshal(&resStr)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
