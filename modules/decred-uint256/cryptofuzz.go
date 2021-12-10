package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "strconv"
    "uint256"
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

//export decred_uint256_Cryptofuzz_GetResult
func decred_uint256_Cryptofuzz_GetResult() *C.char {
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

//export decred_uint256_Cryptofuzz_OpBignumCalc
func decred_uint256_Cryptofuzz_OpBignumCalc(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn0 := decodeBignum(op.BN0)
    if bn0.BitLen() > 256 {
        return
    }
    u0 := new(uint256.Uint256).SetBig(bn0)

    bn1 := decodeBignum(op.BN1)
    if bn1.BitLen() > 256 {
        return
    }
    u1 := new(uint256.Uint256).SetBig(bn1)

    bn2 := decodeBignum(op.BN2)

    res := new(uint256.Uint256).SetBig(bn2)

    var mod byte = 0
    if len(op.Modifier) >= 1 {
        mod = op.Modifier[0]
    }

    if false {
    } else if isAdd(op.CalcOp) {
        if mod % 2 == 0 {
            res = u0.Add(u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res = u0.AddUint64(u1.Uint64())
        }
    } else if isSub(op.CalcOp) {
        if mod % 2 == 0 {
            res = u0.Sub(u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res = u0.SubUint64(u1.Uint64())
        }
    } else if isMul(op.CalcOp) {
        if mod % 2 == 0 {
            res = u0.Mul(u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res = u0.MulUint64(u1.Uint64())
        }
    } else if isDiv(op.CalcOp) {
        if u1.IsZero() {
            return
        }
        if mod % 2 == 0 {
            res = u0.Div(u1)
        } else {
            if !u1.IsUint64() {
                return
            }
            res = u0.DivUint64(u1.Uint64())
        }
    } else if isRShift(op.CalcOp) {
        if !u1.IsUint32() {
            return
        }
        res = u0.Rsh(u1.Uint32())
    } else if isLShift(op.CalcOp) {
        if !u1.IsUint32() {
            return
        }
        res = u0.Lsh(u1.Uint32())
    } else if isLShift1(op.CalcOp) {
        res = u0.Lsh(1)
    } else if isSqr(op.CalcOp) {
        res = u0.Square()
    } else if isNot(op.CalcOp) {
        res = u0.Negate()
    } else if isAnd(op.CalcOp) {
        res = u0.And(u1)
    } else if isOr(op.CalcOp) {
        res = u0.Or(u1)
    } else if isXor(op.CalcOp) {
        res = u0.Xor(u1)
    } else if isNumBits(op.CalcOp) {
        res.SetUint64((uint64)(u0.BitLen()))
    } else if isIsOdd(op.CalcOp) {
        res.Zero()
        if u0.IsOdd() {
            res.AddUint64(1)
        }
    } else if isIsEq(op.CalcOp) {
        res.Zero()
        if u0.Eq(u1) {
            res.AddUint64(1)
        }
    } else if isIsLt(op.CalcOp) {
        res.Zero()
        if u0.Lt(u1) {
            res.AddUint64(1)
        }
    } else if isIsLte(op.CalcOp) {
        res.Zero()
        if u0.LtEq(u1) {
            res.AddUint64(1)
        }
    } else if isIsGt(op.CalcOp) {
        res.Zero()
        if u0.Gt(u1) {
            res.AddUint64(1)
        }
    } else if isIsGte(op.CalcOp) {
        res.Zero()
        if u0.GtEq(u1) {
            res.AddUint64(1)
        }
    } else if isSet(op.CalcOp) {
        if mod % 4 == 0 {
            if !u0.IsUint64() {
                return
            }
            res.SetUint64(u0.Uint64())
        } else if mod % 4 == 1 {
            b := u0.Bytes()
            res.SetBytes(&b)
        } else if mod % 4 == 2 {
            res.SetBig(u0.ToBig())
        } else {
            b := u0.BytesLE()
            res.SetBytesLE(&b)
        }
    } else {
        return
    }

    /* Misc ops */
    if mod % 4 == 0 {
        res.Text(uint256.OutputBaseHex)
    } else if mod % 4 == 1 {
        res.Text(uint256.OutputBaseDecimal)
    } else if mod % 4 == 2 {
        res.Text(uint256.OutputBaseBinary)
    } else {
        res.Text(uint256.OutputBaseOctal)
    }

    //resStr := res.String()
    resStr := res.ToBig().String()
    r2, err := json.Marshal(&resStr)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

func main() { }
