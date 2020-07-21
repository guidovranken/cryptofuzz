package main

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/hmac"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/blake2s"
    "golang.org/x/crypto/hkdf"
    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/pbkdf2"
    "golang.org/x/crypto/ripemd160"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/sha3"
    "hash"
    "hash/adler32"
    "hash/crc32"
    "io"
    "math/big"
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

type OpDigest struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    DigestType uint64
}

type ComponentCipher struct {
    IV ByteSlice
    Key ByteSlice
    CipherType uint64
}

type OpHMAC struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    DigestType uint64
    Cipher ComponentCipher
}

type OpCMAC struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    Cipher ComponentCipher
}

type OpKDF_SCRYPT struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    Password ByteSlice
    Salt ByteSlice
    N uint64
    R uint64
    P uint64
    KeySize uint64
}

type OpKDF_HKDF struct {
    Modifier ByteSlice
    DigestType uint64
    Password ByteSlice
    Salt ByteSlice
    Info ByteSlice
    KeySize uint64
}

type OpKDF_PBKDF2 struct {
    Modifier ByteSlice
    DigestType uint64
    Password ByteSlice
    Salt ByteSlice
    Iterations uint64
    KeySize uint64
}

type OpKDF_ARGON2 struct {
    Modifier ByteSlice
    Password ByteSlice
    Salt ByteSlice
    Type uint8
    Threads uint8
    Memory uint32
    Iterations uint32
    KeySize uint32
}

type OpECC_PrivateToPublic struct {
    Modifier ByteSlice
    CurveType uint64
    Priv string
}

type OpECDSA_Verify struct {
    Modifier ByteSlice
    CurveType uint64
    Pub_X string
    Pub_Y string
    Cleartext ByteSlice
    Sig_R string
    Sig_S string
}

type OpBignumCalc struct {
    Modifier ByteSlice
    CalcOp uint64
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

//export Golang_Cryptofuzz_GetResult
func Golang_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

func toHashFunc(digestType uint64) (func() hash.Hash, error) {
    if false {
    } else if isMD4(digestType) {
        return md4.New, nil
    } else if isMD5(digestType) {
        return md5.New, nil
    } else if isRIPEMD160(digestType) {
        return ripemd160.New, nil
    } else if isSHA1(digestType) {
        return sha1.New, nil
    } else if isSHA256(digestType) {
        return sha256.New, nil
    } else if isSHA512(digestType) {
        return sha512.New, nil
    } else if isSHA3_224(digestType) {
        return sha3.New224, nil
    } else if isSHA3_256(digestType) {
        return sha3.New256, nil
    } else if isSHA3_384(digestType) {
        return sha3.New384, nil
    } else if isSHA3_512(digestType) {
        return sha3.New512, nil
    } else if isKECCAK_256(digestType) {
        return sha3.NewLegacyKeccak256, nil
    } else if isKECCAK_512(digestType) {
        return sha3.NewLegacyKeccak512, nil
    }

    return nil, fmt.Errorf("Unsupported digest ID")
}

func toHashInstance(digestType uint64) (hash.Hash, error) {

    if false {
    } else if isCRC32(digestType) {
        return crc32.NewIEEE(), nil
    } else if isADLER32(digestType) {
        return adler32.New(), nil
    } else if isBLAKE2S128(digestType) {
        return blake2s.New128(nil)
    } else if isBLAKE2S256(digestType) {
        return blake2s.New256(nil)
    } else if isBLAKE2B256(digestType) {
        return blake2b.New256(nil)
    } else if isBLAKE2B384(digestType) {
        return blake2b.New384(nil)
    } else if isBLAKE2B512(digestType) {
        return blake2b.New512(nil)
    }

    h, err := toHashFunc(digestType)
    if err != nil {
        return nil, err
    }
    return h(), nil
}

func slice(modifier ByteSlice, in ByteSlice) []SliceOpt {
    ret := make([]SliceOpt, 0)
    modifierPos := 0
    pos := uint32(0)

    for uint32(len(in)) - pos > 0 {
        curLength := uint32(len(in)) - pos

        if modifierPos + 4 < len(modifier) {
            curLength = binary.LittleEndian.Uint32(modifier[modifierPos:modifierPos+4]) % (curLength+1)
            modifierPos += 4
        }

        var opt byte = 0
        if modifierPos + 1 < len(modifier) {
            opt = modifier[modifierPos]
            modifierPos += 1
        }

        sliceopt := SliceOpt{in[pos:pos+curLength], opt}

        ret = append(ret, sliceopt)
        pos += curLength
    }

    return ret
}

func digest(modifier ByteSlice, cleartext ByteSlice, h hash.Hash) {
    slices := slice(modifier, cleartext)
    var again bool = true
    loops := 0
    for again == true {
        again = false
        for i := 0; i < len(slices); i++ {
            h.Write(slices[i].slice)
            if loops < 3 && slices[i].opt & 1 == 1 {
                h.Reset()
                again = true
                loops += 1
                break
            }
        }
    }

    res := ByteSlice(h.Sum(nil))

    setResult(res)
}

func digestShake(modifier ByteSlice, cleartext ByteSlice, outsize uint64, h sha3.ShakeHash) {
    slices := slice(modifier, cleartext)
    var again bool = true
    loops := 0
    for again == true {
        again = false
        for i := 0; i < len(slices); i++ {
            h.Write(slices[i].slice)
            if loops < 3 && slices[i].opt & 1 == 1 {
                h.Reset()
                again = true
                loops += 1
                break
            }
            if slices[i].opt & 2 == 2 {
                clone := h.Clone()
                if slices[i].opt & 4 == 4 {
                    h.Reset()
                }
                h = clone
            }
        }
    }

    res := make([]byte, outsize)
    h.Read(res)

    setResult(res)
}

func unmarshal(in []byte, op interface{}) {
    err := json.Unmarshal(in, &op)
    if err != nil {
        panic("Cannot unmarshal JSON, which is expected to be well-formed")
    }
}

//export Golang_Cryptofuzz_OpDigest
func Golang_Cryptofuzz_OpDigest(in []byte) {
    resetResult()

    var op OpDigest
    unmarshal(in, &op)

    if isSHAKE128(op.DigestType) {
        h := sha3.NewShake128()
        digestShake(op.Modifier, op.Cleartext, 16, h)
    } else if isSHAKE256(op.DigestType) {
        h := sha3.NewShake256()
        digestShake(op.Modifier, op.Cleartext, 32, h)
    } else {
        h, err := toHashInstance(op.DigestType)
        if err != nil {
            return
        }

        digest(op.Modifier, op.Cleartext, h)
    }
}

//export Golang_Cryptofuzz_OpHMAC
func Golang_Cryptofuzz_OpHMAC(in []byte) {
    resetResult()

    var op OpHMAC
    unmarshal(in, &op)

    hash, err := toHashFunc(op.DigestType)
    if err != nil {
        return
    }

    hmac := hmac.New(hash, op.Cipher.Key)

    slices := slice(op.Modifier, op.Cleartext)
    var again bool = true
    loops := 0
    for again == true {
        again = false
        for i := 0; i < len(slices); i++ {
            hmac.Write(slices[i].slice)
            if loops < 3 && slices[i].opt & 1 == 1 {
                hmac.Reset()
                again = true
                loops += 1
                break
            }
        }
    }

    mac := hmac.Sum(nil)

    setResult(mac)
}

//export Golang_Cryptofuzz_OpCMAC
func Golang_Cryptofuzz_OpCMAC(in []byte) {
    resetResult()

    var op OpCMAC
    unmarshal(in, &op)

    /* TODO */
}

//export Golang_Cryptofuzz_OpKDF_SCRYPT
func Golang_Cryptofuzz_OpKDF_SCRYPT(in []byte) {
    resetResult()

    var op OpKDF_SCRYPT
    unmarshal(in, &op)

    /* division by zero. TODO report? */
    if op.R == 0 || op.P == 0 {
        return
    }

    res, err := scrypt.Key(op.Password, op.Salt, int(op.N), int(op.R), int(op.P), int(op.KeySize))
    if err != nil {
        return
    }

    setResult(res)
}

//export Golang_Cryptofuzz_OpKDF_HKDF
func Golang_Cryptofuzz_OpKDF_HKDF(in []byte) {
    resetResult()

    var op OpKDF_HKDF
    unmarshal(in, &op)

    h, err := toHashFunc(op.DigestType)
    if err != nil {
        return
    }

    hkdf := hkdf.New(h, op.Password, op.Salt, op.Info)
    key := make([]byte, op.KeySize)
    if _, err := io.ReadFull(hkdf, key); err != nil {
        return
    }

    setResult(key)
}

//export Golang_Cryptofuzz_OpKDF_PBKDF2
func Golang_Cryptofuzz_OpKDF_PBKDF2(in []byte) {
    resetResult()

    var op OpKDF_PBKDF2
    unmarshal(in, &op)

    h, err := toHashFunc(op.DigestType)
    if err != nil {
        return
    }

    key := pbkdf2.Key(op.Password, op.Salt, int(op.Iterations), int(op.KeySize), h)

    setResult(key)
}

//export Golang_Cryptofuzz_OpKDF_ARGON2
func Golang_Cryptofuzz_OpKDF_ARGON2(in []byte) {
    resetResult()

    var op OpKDF_ARGON2
    unmarshal(in, &op)

    if op.Iterations == 0 {
        return
    }

    if op.Threads == 0 {
        return
    }

    /* KeySize == 0 crashes, see https://github.com/golang/go/issues/33583 */
    if op.KeySize == 0 {
        return
    }

    var key []byte
    if op.Type == 1 {
        /* Argon2_i */
        key = argon2.Key(op.Password, op.Salt, op.Iterations, op.Memory, op.Threads, op.KeySize)
    } else if op.Type == 2 {
        /* Argon2_id */
        key = argon2.IDKey(op.Password, op.Salt, op.Iterations, op.Memory, op.Threads, op.KeySize)
    } else {
        return
    }

    setResult(key)
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

func toCurve(curveType uint64) (elliptic.Curve, error) {
    if issecp224r1(curveType) {
        return elliptic.P224(), nil
    } else if isx962_p256v1(curveType) {
        return elliptic.P256(), nil
    } else if issecp384r1(curveType) {
        return elliptic.P384(), nil
    } else if issecp521r1(curveType) {
        return elliptic.P521(), nil
    } else {
        return nil, fmt.Errorf("Unsupported digest ID")
    }

}

//export Golang_Cryptofuzz_OpECC_PrivateToPublic
func Golang_Cryptofuzz_OpECC_PrivateToPublic(in []byte) {
    resetResult()

    var op OpECC_PrivateToPublic
    unmarshal(in, &op)

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }

    priv := decodeBignum(op.Priv)
    x, y := curve.ScalarBaseMult(priv.Bytes())

    res := make([]string, 2)
    res[0] = x.String()
    res[1] = y.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Golang_Cryptofuzz_OpECDSA_Verify
func Golang_Cryptofuzz_OpECDSA_Verify(in []byte) {
    resetResult()

    var op OpECDSA_Verify
    unmarshal(in, &op)

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }


    sigR := decodeBignum(op.Sig_R)
    sigS := decodeBignum(op.Sig_S)

    pubKey := new(ecdsa.PublicKey)
    pubKey.Curve = curve
    pubKey.X = decodeBignum(op.Pub_X)
    pubKey.Y = decodeBignum(op.Pub_Y)

    ecdsa.Verify(pubKey, op.Cleartext, sigR, sigS)

    /* TODO set result */
}

func op_ADD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Add(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.Add(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_SUB(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Sub(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.Sub(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_MUL(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Mul(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.Mul(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_DIV(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if ( BN1.Cmp(big.NewInt(0)) != 0 ) {
        if direct {
            res.Div(BN0, BN1)
        } else {
            tmp := big.NewInt(0)
            tmp.Div(BN0, BN1)
            res.Set(tmp)
        }
    } else {
        return false
    }
    return true
}

func op_MOD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.Cmp(big.NewInt(0)) >= 0 && BN1.Cmp(big.NewInt(0)) > 0 {
        if direct {
            res.Mod(BN0, BN1)
        } else {
            tmp := big.NewInt(0)
            tmp.Mod(BN0, BN1)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_EXP_MOD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.Cmp(big.NewInt(0)) > 0 && BN1.Cmp(big.NewInt(0)) > 0 && BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            res.Exp(BN0, BN1, BN2)
        } else {
            tmp := big.NewInt(0)
            tmp.Exp(BN0, BN1, BN2)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_LSHIFT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Lsh(BN0, 1)
    } else {
        tmp := big.NewInt(0)
        tmp.Lsh(BN0, 1)
        res.Set(tmp)
    }
    return true
}

func op_RSHIFT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    return false;
}

func op_GCD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.Cmp(big.NewInt(0)) > 0 && BN1.Cmp(big.NewInt(0)) > 0 {
        if direct {
            res.GCD(nil, nil, BN0, BN1)
        } else {
            tmp := big.NewInt(0)
            tmp.GCD(nil, nil, BN0, BN1)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_MOD_ADD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            res.Add(BN0, BN1)
            res.Mod(res, BN2)
        } else {
            tmp := big.NewInt(0)
            tmp.Add(BN0, BN1)
            tmp.Mod(tmp, BN2)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_EXP(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    thousand := big.NewInt(1000)
    if BN0.Cmp(big.NewInt(0)) > 0 && BN0.Cmp(thousand) < 0 && BN1.Cmp(big.NewInt(0)) > 0 && BN1.Cmp(thousand) < 0 {
        if direct {
            res.Exp(BN0, BN1, nil)
            return true
        } else {
            tmp := big.NewInt(0)
            tmp.Exp(BN0, BN1, nil)
            res.Set(tmp)
            return true
        }
    } else {
        return false
    }
}


func op_SQR(res *big.Int, BN1 *big.Int, BN2 *big.Int, BN3 *big.Int, direct bool) bool {
    if direct {
        res.Exp(BN1, big.NewInt(2), nil)
    } else {
        tmp := big.NewInt(0)
        tmp.Exp(BN1, big.NewInt(2), nil)
        res.Set(tmp)
    }
    return true
}

func op_NEG(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Neg(BN0)
    } else {
        tmp := big.NewInt(0)
        tmp.Neg(BN0)
        res.Set(tmp)
    }
    return true
}

func op_ABS(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Abs(BN0)
    } else {
        tmp := big.NewInt(0)
        tmp.Abs(BN0)
        res.Set(tmp)
    }
    return true
}

func op_IS_PRIME(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    /* "ProbablyPrime is 100% accurate for inputs less than 2⁶⁴."
     * https://golang.org/pkg/math/big/#Int.ProbablyPrime
    */
    max64 := big.NewInt(0).Lsh( big.NewInt(1), 64 )
    max64.Sub(max64, big.NewInt(1))
    if BN0.Cmp(big.NewInt(0)) > 0 && BN0.Cmp(max64) < 0 {
        is_prime := false
        if direct {
            is_prime = BN0.ProbablyPrime(1)
        } else {
            tmp := big.NewInt(0).Set(BN0)
            is_prime = tmp.ProbablyPrime(1)
        }
        if is_prime {
            res = big.NewInt(1)
        } else {
            res = big.NewInt(0)
        }
        return true
    } else {
        return false
    }
}

func op_MOD_SUB(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            res.Sub(BN0, BN1)
            res.Mod(res, BN2)
        } else {
            tmp := big.NewInt(0)
            tmp.Sub(BN0, BN1)
            tmp.Mod(tmp, BN2)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_SWAP(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    tmp := new(big.Int).Set(res)
    res.Set(BN0)
    BN0.Set(tmp)
    return true
}

func op_MOD_MUL(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            res.Mul(BN0, BN1)
            res.Mod(res, BN2)
        } else {
            tmp := big.NewInt(0)
            tmp.Mul(BN0, BN1)
            tmp.Mod(tmp, BN2)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_SET_BIT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.Cmp(big.NewInt(0)) >= 0 && BN0.Cmp(big.NewInt(1000)) <= 0 && BN0.Cmp(big.NewInt(0)) >= 0 {
        pos := BN0.Int64()

        if direct {
            res.SetBit(res, int(pos), 1)
        } else {
            tmp := res
            tmp.SetBit(res, int(pos), 1)
            res.Set(tmp)
        }

        return true
    } else {
        return false
    }
}

func op_INV_MOD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        if res.ModInverse(BN0, BN1) == nil {
            return false
        }
    } else {
        tmp := big.NewInt(0)
        if tmp.ModInverse(BN0, BN1) == nil {
            return false
        }
        res.Set(tmp)
    }
    return true
}

func op_MOD_SQRT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    /* XXX requires primality check of BN1 */
    return false;
    /* BN1 must be odd */
    if BN1.Bit(0) == 1 {
        if direct {
            if res.ModSqrt(BN0, BN1) == nil {
                return false
            }
        } else {
            tmp := big.NewInt(0)
            if tmp.ModSqrt(BN0, BN1) == nil {
                return false
            }
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_SQRT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.Cmp(big.NewInt(0)) >= 0 {
        if direct {
            res.Sqrt(BN0)
        } else {
            tmp := big.NewInt(0)
            tmp.Sqrt(BN0)
            res.Set(tmp)
        }
        return true
    } else {
        return false
    }
}

func op_AND(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.And(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.And(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_OR(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Or(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.Or(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_XOR(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if direct {
        res.Xor(BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.Xor(BN0, BN1)
        res.Set(tmp)
    }
    return true
}

//export Golang_Cryptofuzz_OpBignumCalc
func Golang_Cryptofuzz_OpBignumCalc(in []byte) {
    resetResult()

    var op OpBignumCalc
    unmarshal(in, &op)

    bn := make([]*big.Int, 4)
    bn[0] = decodeBignum(op.BN0)
    bn[1] = decodeBignum(op.BN1)
    bn[2] = decodeBignum(op.BN2)
    bn[3] = decodeBignum(op.BN3)

    res := new(big.Int)

    success := false
    direct := false

    if len(op.Modifier) >= 1 {
        if op.Modifier[0] & 1 == 1 {
            direct = true
        }
    }

    if false {
    } else if isAdd(op.CalcOp) {
        success = op_ADD(res, bn[0], bn[1], bn[2], direct)
    } else if isSub(op.CalcOp) {
        success = op_SUB(res, bn[0], bn[1], bn[2], direct)
    } else if isMul(op.CalcOp) {
        success = op_MUL(res, bn[0], bn[1], bn[2], direct)
    } else if isDiv(op.CalcOp) {
        success = op_DIV(res, bn[0], bn[1], bn[2], direct)
    } else if isMod(op.CalcOp) {
        success = op_MOD(res, bn[0], bn[1], bn[2], direct)
    } else if isExpMod(op.CalcOp) {
        success = op_EXP_MOD(res, bn[0], bn[1], bn[2], direct)
    } else if isRShift(op.CalcOp) {
        success = op_RSHIFT(res, bn[0], bn[1], bn[2], direct)
    } else if isGCD(op.CalcOp) {
        success = op_GCD(res, bn[0], bn[1], bn[2], direct)
    } else if isAddMod(op.CalcOp) {
        success = op_MOD_ADD(res, bn[0], bn[1], bn[2], direct)
    } else if isExp(op.CalcOp) {
        success = op_EXP(res, bn[0], bn[1], bn[2], direct)
    } else if isSqr(op.CalcOp) {
        success = op_SQR(res, bn[0], bn[1], bn[2], direct)
    } else if isNeg(op.CalcOp) {
        success = op_NEG(res, bn[0], bn[1], bn[2], direct)
    } else if isAbs(op.CalcOp) {
        success = op_ABS(res, bn[0], bn[1], bn[2], direct)
    } else if isSubMod(op.CalcOp) {
        success = op_MOD_SUB(res, bn[0], bn[1], bn[2], direct)
    } else if isMulMod(op.CalcOp) {
        success = op_MOD_MUL(res, bn[0], bn[1], bn[2], direct)
    } else if isInvMod(op.CalcOp) {
        success = op_INV_MOD(res, bn[0], bn[1], bn[2], direct)
    } else if isSqrtMod(op.CalcOp) {
        success = op_MOD_SQRT(res, bn[0], bn[1], bn[2], direct)
    } else if isSqrt(op.CalcOp) {
        success = op_SQRT(res, bn[0], bn[1], bn[2], direct)
    } else if isAnd(op.CalcOp) {
        success = op_AND(res, bn[0], bn[1], bn[2], direct)
    } else if isOr(op.CalcOp) {
        success = op_OR(res, bn[0], bn[1], bn[2], direct)
    } else if isXor(op.CalcOp) {
        success = op_XOR(res, bn[0], bn[1], bn[2], direct)
    } else if isSetBit(op.CalcOp) {
        success = op_SET_BIT(res, bn[0], bn[1], bn[2], direct)
    }

    if success == false {
        return
    }

    resStr := res.String()
    r2, err := json.Marshal(&resStr)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

/*
testing
func main() {
    for j := 0; j < 5000; j++ {
        cleartext := make([]byte, rand.Intn(1024))
        rand.Read(cleartext)

        prev := ByteSlice{}
        for i := 0; i < 5000; i++ {
            modifier := make([]byte, rand.Intn(1024))
            rand.Read(modifier)
            cur := digest(modifier, cleartext, md5.New())
            if i > 0 && !bytes.Equal(cur, prev) {
                panic("")
            }
            prev = cur
        }
    }
}
*/

func main() { }
