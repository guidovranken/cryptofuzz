package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/dsa"
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
    "hash/crc64"
    "hash/fnv"
    "io"
    "math"
    "math/big"
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

type OpDigest struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    DigestType Type
}

type ComponentCipher struct {
    IV ByteSlice
    Key ByteSlice
    CipherType Type
}

type OpHMAC struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    DigestType Type
    Cipher ComponentCipher
}

type OpSymmetricEncrypt struct {
    Modifier ByteSlice
    Cleartext ByteSlice
    Cipher ComponentCipher
    Aad_Enabled bool
    Aad ByteSlice
    CiphertextSize uint64
    Tagsize_Enabled bool
    Tagsize uint64
}

type OpSymmetricDecrypt struct {
    Modifier ByteSlice
    Ciphertext ByteSlice
    Cipher ComponentCipher
    Aad_Enabled bool
    Aad ByteSlice
    CiphertextSize uint64
    Tag_Enabled bool
    Tag ByteSlice
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
    DigestType Type
    Password ByteSlice
    Salt ByteSlice
    Info ByteSlice
    KeySize uint64
}

type OpKDF_PBKDF2 struct {
    Modifier ByteSlice
    DigestType Type
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
    CurveType Type
    Priv string
}

type OpECDSA_Verify struct {
    Modifier ByteSlice
    CurveType Type
    DigestType Type
    Pub_X string
    Pub_Y string
    Cleartext ByteSlice
    Sig_R string
    Sig_S string
}

type OpECDSA_Sign struct {
    Modifier ByteSlice
    CurveType Type
    DigestType Type
    Priv string
    Cleartext ByteSlice
}

type ECDSA_Signature struct {
    Pub [2]string `json:"pub"`
    Signature [2]string `json:"signature"`
}

type OpBignumCalc struct {
    Modifier ByteSlice
    CalcOp Type
    BN0 string
    BN1 string
    BN2 string
    BN3 string
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

type OpDSA_Verify struct {
    Modifier ByteSlice
    P string
    Q string
    G string
    Pub string
    Cleartext ByteSlice
    Sig_R string
    Sig_S string
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

func toHashFunc(digestType Type) (func() hash.Hash, error) {
    if false {
    } else if isMD4(digestType) {
        return md4.New, nil
    } else if isMD5(digestType) {
        return md5.New, nil
    } else if isRIPEMD160(digestType) {
        return ripemd160.New, nil
    } else if isSHA1(digestType) {
        return sha1.New, nil
    } else if isSHA224(digestType) {
        return sha256.New224, nil
    } else if isSHA256(digestType) {
        return sha256.New, nil
    } else if isSHA384(digestType) {
        return sha512.New384, nil
    } else if isSHA512(digestType) {
        return sha512.New, nil
    } else if isSHA512_224(digestType) {
        return sha512.New512_224, nil
    } else if isSHA512_256(digestType) {
        return sha512.New512_256, nil
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

func toHashInstance(digestType Type) (hash.Hash, error) {

    if false {
    } else if isCRC32(digestType) {
        return crc32.NewIEEE(), nil
    } else if isCRC64(digestType) {
        tabISO := crc64.MakeTable(crc64.ISO)
        return crc64.New(tabISO), nil
    } else if isFNV32(digestType) {
        return fnv.New32(), nil
    } else if isFNVA32(digestType) {
        return fnv.New32a(), nil
    } else if isFNV64(digestType) {
        return fnv.New64(), nil
    } else if isFNVA64(digestType) {
        return fnv.New64a(), nil
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

//export Golang_Cryptofuzz_OpSymmetricEncrypt
func Golang_Cryptofuzz_OpSymmetricEncrypt(in []byte) {
    resetResult()

    var op OpSymmetricEncrypt
    unmarshal(in, &op)

    if isAES_128_GCM(op.Cipher.CipherType) {
        block, err := aes.NewCipher(op.Cipher.Key)
        if err != nil {
            return
        }

        var aead cipher.AEAD

        if len(op.Cipher.IV) == 12 {
            if op.Tagsize != 16 {
                aead, err = cipher.NewGCMWithTagSize(block, int(op.Tagsize))
            } else {
                aead, err = cipher.NewGCM(block)
            }
        } else {
            if op.Tagsize != 16 {
                return
            }
            aead, err = cipher.NewGCMWithNonceSize(block, len(op.Cipher.IV))
        }

        if err != nil {
            return
        }

        ciphertext := aead.Seal(nil, op.Cipher.IV, op.Cleartext, op.Aad)
        if len(ciphertext) != len(op.Cleartext) + int(op.Tagsize) {
            panic("Unexpected AES-GCM ciphertext")
        }

        setResult(ciphertext)
    }
}

//export Golang_Cryptofuzz_OpSymmetricDecrypt
func Golang_Cryptofuzz_OpSymmetricDecrypt(in []byte) {
    resetResult()

    var op OpSymmetricDecrypt
    unmarshal(in, &op)

    if isAES_128_GCM(op.Cipher.CipherType) {
        block, err := aes.NewCipher(op.Cipher.Key)
        if err != nil {
            return
        }

        var aead cipher.AEAD

        if len(op.Cipher.IV) == 12 {
            if len(op.Tag) != 16 {
                aead, err = cipher.NewGCMWithTagSize(block, len(op.Tag))
            } else {
                aead, err = cipher.NewGCM(block)
            }
        } else {
            if len(op.Tag) != 16 {
                return
            }
            aead, err = cipher.NewGCMWithNonceSize(block, len(op.Cipher.IV))
        }

        if err != nil {
            return
        }

        ciphertext := append(op.Ciphertext, op.Tag...)

        cleartext, err := aead.Open(nil, op.Cipher.IV, ciphertext, op.Aad)
        if err != nil {
            return
        }

        setResult(cleartext)
    }
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
    } else if s == "-" {
        s = "-0"
    }

    bn, ok := new(big.Int).SetString(s, 10)
    if ok == false {
        panic("Cannot decode bignum")
    }
    return bn
}

func toCurve(curveType Type) (elliptic.Curve, error) {
    if issecp224r1(curveType) {
        return elliptic.P224(), nil
    } else if isx962_p256v1(curveType) {
        return elliptic.P256(), nil
    } else if issecp256r1(curveType) {
        return elliptic.P256(), nil
    } else if issecp384r1(curveType) {
        return elliptic.P384(), nil
    } else if issecp521r1(curveType) {
        return elliptic.P521(), nil
    } else {
        return nil, fmt.Errorf("Unsupported curve ID")
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

    if isNULL(op.DigestType) == false {
        return
    }

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

    var res bool
    if curve.IsOnCurve(pubKey.X, pubKey.Y) == false {
        res = false
    } else {
        res = ecdsa.Verify(pubKey, op.Cleartext, sigR, sigS)
    }

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Golang_Cryptofuzz_OpECDSA_Sign
func Golang_Cryptofuzz_OpECDSA_Sign(in []byte) {
    resetResult()

    var op OpECDSA_Sign
    unmarshal(in, &op)

    if isNULL(op.DigestType) == false {
        return
    }

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }

    priv := decodeBignum(op.Priv)
    x, y := curve.ScalarBaseMult(priv.Bytes())

    if x.String() == "0" { return } /* XXX */

    var priv_ecdsa ecdsa.PrivateKey
    priv_ecdsa.D = priv
    priv_ecdsa.PublicKey.Curve = curve

    randreader := bytes.NewReader(op.Modifier)

    r, s, err := ecdsa.Sign(randreader, &priv_ecdsa, op.Cleartext)
    if err != nil {
        return
    }

    var res ECDSA_Signature
    res.Pub[0] = x.String()
    res.Pub[1] = y.String()

    res.Signature[0] = r.String()
    res.Signature[1] = s.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
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
    if direct {
        res.GCD(nil, nil, BN0, BN1)
    } else {
        tmp := big.NewInt(0)
        tmp.GCD(nil, nil, BN0, BN1)
        res.Set(tmp)
    }
    return true
}

func op_ExtGCD_X(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    tmp := big.NewInt(0)
    x := big.NewInt(0)
    y := big.NewInt(0)
    tmp.GCD(x, y, BN0, BN1)
    res.Set(x)
    return true
}

func op_ExtGCD_Y(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    tmp := big.NewInt(0)
    x := big.NewInt(0)
    y := big.NewInt(0)
    tmp.GCD(x, y, BN0, BN1)
    res.Set(y)
    return true
}

func op_MOD_ADD(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    r := new(big.Int)
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            r.Add(BN0, BN1)
            r.Mod(r, BN2)
            res.Set(r)
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
    is_prime := false
    if direct {
        is_prime = BN0.ProbablyPrime(1)
    } else {
        tmp := big.NewInt(0).Set(BN0)
        is_prime = tmp.ProbablyPrime(1)
    }
    if is_prime {
        res.SetUint64(1)
    } else {
        res.SetUint64(0)
    }
    return true
}

func op_MOD_SUB(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    r := new(big.Int)
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            r.Sub(BN0, BN1)
            r.Mod(r, BN2)
            res.Set(r)
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
    r := new(big.Int)
    if BN2.Cmp(big.NewInt(0)) != 0 {
        if direct {
            r.Mul(BN0, BN1)
            r.Mod(r, BN2)
            res.Set(r)
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
    if BN0.Cmp(big.NewInt(0)) >= 0 && BN1.Cmp(big.NewInt(9999)) <= 0 && BN1.Cmp(big.NewInt(0)) >= 0 {
        pos := BN1.Int64()

        res.Set(BN0)

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
    if BN0.Cmp(big.NewInt(0)) < 0 && BN1.Cmp(big.NewInt(0)) == 0 {
        /* Avoid panic */
        return false
    }

    if BN0.Cmp(big.NewInt(1)) == 0 && BN1.Cmp(big.NewInt(0)) == 0 {
        /* Golang incorrectly states InvMod(1, 0) is 1 */
        return false
    }

    if direct {
        if res.ModInverse(BN0, BN1) == nil {
            /* Inverse does not exist */
            res.SetUint64(0)
            return true
        }
    } else {
        tmp := big.NewInt(0)
        if tmp.ModInverse(BN0, BN1) == nil {
            /* Inverse does not exist */
            res.SetUint64(0)
            return true
        }
        res.Set(tmp)
    }
    return true
}

func op_MOD_SQRT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {

    if BN1.Bit(0) == 0 {
        return false
    }
    if BN1.Cmp(big.NewInt(0)) <= 0 {
        return false
    }

    max64 := big.NewInt(0).SetUint64(math.MaxInt64)

    if BN1.Cmp(max64) >= 0 {
        return false
    }
    if BN1.ProbablyPrime(1) == false {
        return false
    }

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

    {
        tmp1 := big.NewInt(0)
        tmp1.Mod(BN0, BN1)

        tmp2 := big.NewInt(0)
        tmp2.Exp(res, big.NewInt(2), BN1)

        if tmp1.Cmp(tmp2) != 0 {
            panic("Invalid modular square root")
        }
    }

    return true
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

func op_NUM_BITS(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    res.SetInt64((int64)(BN0.BitLen()))
    return true
}

func op_CMP(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    res.SetInt64((int64)(BN0.Cmp(BN1)))
    return true
}

func op_CMP_ABS(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    res.SetInt64((int64)(BN0.CmpAbs(BN1)))
    return true
}

func op_BIT(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN1.IsInt64() == false {
        return false
    }
    pos := BN1.Int64()
    if pos < 0 {
        return false
    }
    if pos > math.MaxInt32 {
        return false
    }

    res.SetInt64((int64)(BN0.Bit((int)(pos))))
    return true
}

func op_JACOBI(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN1.Bit(0) == 0 {
        return false
    }

    res.SetInt64((int64)(big.Jacobi(BN0, BN1)))
    return true
}

func op_FACTORIAL(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.IsInt64() == false {
        return false
    }

    bn0 := BN0.Int64()

    if bn0 < 1 {
        return false
    }
    if bn0 > 1500 {
        return false
    }

    if direct {
        res.MulRange(1, bn0)
    } else {
        tmp := big.NewInt(0)
        tmp.MulRange(1, bn0)
        res.Set(tmp)
    }
    return true
}

func op_BIN_COEFF(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool) bool {
    if BN0.IsInt64() == false {
        return false
    }

    bn0 := BN0.Int64()

    if bn0 > 100000 {
        return false
    }

    if BN1.IsInt64() == false {
        return false
    }

    bn1 := BN1.Int64()

    if bn1 > 100000 {
        return false
    }

    if direct {
        res.Binomial(bn0, bn1)
    } else {
        tmp := big.NewInt(0)
        tmp.Binomial(bn0, bn1)
        res.Set(tmp)
    }
    return true
}

func op_SET(res *big.Int, BN0 *big.Int, BN1 *big.Int, BN2 *big.Int, direct bool, modifier byte, base byte) bool {
    modifier %= 6

    if modifier == 0 {
        if BN0.IsInt64() == false {
            return false
        }

        res.SetInt64(BN0.Int64())
    } else if modifier == 1 {
        if BN0.IsUint64() == false {
            return false
        }

        res.SetUint64(BN0.Uint64())
    } else if modifier == 2 {
        /* "Base must be between 2 and 62, inclusive" */
        base %= 60
        base += 2
        str := BN0.Text(int(base))
        _, err := res.SetString(str, int(base))
        if err == false {
            panic("SetString failed")
        }
    } else if modifier == 3 {
        if BN0.Cmp(big.NewInt(0)) < 0 {
            return false
        }
        res.SetBits(BN0.Bits())
    } else if modifier == 4 {
        if BN0.Cmp(big.NewInt(0)) < 0 {
            return false
        }
        res.SetBytes(BN0.Bytes())
    } else if modifier == 5 {
        encoded, err := BN0.GobEncode()
        if err != nil {
            return false
        }
        err = res.GobDecode(encoded)
        if err != nil {
            return false
        }
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
    var alias_BN0 uint8 = 0
    var alias_BN1 uint8 = 0
    var alias_BN2 uint8 = 0
    var alias_res uint8 = 0

    if len(op.Modifier) >= 1 {
        if op.Modifier[0] & 1 == 1 {
            direct = true
        }
    }
    if len(op.Modifier) >= 2 {
        alias_BN0 = op.Modifier[1]
    }
    if len(op.Modifier) >= 3 {
        alias_BN1 = op.Modifier[2]
    }
    if len(op.Modifier) >= 4 {
        alias_BN2 = op.Modifier[3]
    }
    if len(op.Modifier) >= 5 {
        alias_res = op.Modifier[4]
    }

    var BN0 *big.Int
    if bn[0].Cmp(bn[alias_BN0 % 4]) == 0 {
        BN0 = bn[alias_BN0 % 4]
    } else {
        BN0 = bn[0]
    }

    var BN1 *big.Int
    if bn[1].Cmp(bn[alias_BN1 % 4]) == 0 {
        BN1 = bn[alias_BN1 % 4]
    } else {
        BN1 = bn[1]
    }

    var BN2 *big.Int
    if bn[2].Cmp(bn[alias_BN2 % 4]) == 0 {
        BN2 = bn[alias_BN2 % 4]
    } else {
        BN2 = bn[2]
    }

    if !isSqrtMod(op.CalcOp) {
        if alias_res != 0 {
            res = bn[alias_res % 4]
        }
    }

    if false {
    } else if isAdd(op.CalcOp) {
        success = op_ADD(res, BN0, BN1, BN2, direct)
    } else if isSub(op.CalcOp) {
        success = op_SUB(res, BN0, BN1, BN2, direct)
    } else if isMul(op.CalcOp) {
        success = op_MUL(res, BN0, BN1, BN2, direct)
    } else if isDiv(op.CalcOp) {
        success = op_DIV(res, BN0, BN1, BN2, direct)
    } else if isMod(op.CalcOp) {
        success = op_MOD(res, BN0, BN1, BN2, direct)
    } else if isExpMod(op.CalcOp) {
        success = op_EXP_MOD(res, BN0, BN1, BN2, direct)
    } else if isRShift(op.CalcOp) {
        success = op_RSHIFT(res, BN0, BN1, BN2, direct)
    } else if isGCD(op.CalcOp) {
        success = op_GCD(res, BN0, BN1, BN2, direct)
    } else if isExtGCD_X(op.CalcOp) {
        success = op_ExtGCD_X(res, BN0, BN1, BN2, direct)
    } else if isExtGCD_Y(op.CalcOp) {
        success = op_ExtGCD_Y(res, BN0, BN1, BN2, direct)
    } else if isAddMod(op.CalcOp) {
        success = op_MOD_ADD(res, BN0, BN1, BN2, direct)
    } else if isExp(op.CalcOp) {
        success = op_EXP(res, BN0, BN1, BN2, direct)
    } else if isSqr(op.CalcOp) {
        success = op_SQR(res, BN0, BN1, BN2, direct)
    } else if isNeg(op.CalcOp) {
        success = op_NEG(res, BN0, BN1, BN2, direct)
    } else if isAbs(op.CalcOp) {
        success = op_ABS(res, BN0, BN1, BN2, direct)
    } else if isSubMod(op.CalcOp) {
        success = op_MOD_SUB(res, BN0, BN1, BN2, direct)
    } else if isMulMod(op.CalcOp) {
        success = op_MOD_MUL(res, BN0, BN1, BN2, direct)
    } else if isInvMod(op.CalcOp) {
        success = op_INV_MOD(res, BN0, BN1, BN2, direct)
    } else if isSqrtMod(op.CalcOp) {
        success = op_MOD_SQRT(res, BN0, BN1, BN2, direct)
    } else if isSqrt(op.CalcOp) {
        success = op_SQRT(res, BN0, BN1, BN2, direct)
    } else if isAnd(op.CalcOp) {
        success = op_AND(res, BN0, BN1, BN2, direct)
    } else if isOr(op.CalcOp) {
        success = op_OR(res, BN0, BN1, BN2, direct)
    } else if isXor(op.CalcOp) {
        success = op_XOR(res, BN0, BN1, BN2, direct)
    } else if isSetBit(op.CalcOp) {
        success = op_SET_BIT(res, BN0, BN1, BN2, direct)
    } else if isNumBits(op.CalcOp) {
        success = op_NUM_BITS(res, BN0, BN1, BN2, direct)
    } else if isCmp(op.CalcOp) {
        success = op_CMP(res, BN0, BN1, BN2, direct)
    } else if isCmpAbs(op.CalcOp) {
        success = op_CMP_ABS(res, BN0, BN1, BN2, direct)
    } else if isBit(op.CalcOp) {
        success = op_BIT(res, BN0, BN1, BN2, direct)
    } else if isJacobi(op.CalcOp) {
        success = op_JACOBI(res, BN0, BN1, BN2, direct)
    } else if isFactorial(op.CalcOp) {
        success = op_FACTORIAL(res, BN0, BN1, BN2, direct)
    } else if isBinCoeff(op.CalcOp) {
        success = op_BIN_COEFF(res, BN0, BN1, BN2, direct)
    } else if isSet(op.CalcOp) {
        var modifier byte = 0
        if len(op.Modifier) >= 2 {
            modifier = op.Modifier[1]
        }
        var base byte = 0
        if len(op.Modifier) >= 3 {
            base = op.Modifier[2]
        }
        success = op_SET(res, BN0, BN1, BN2, direct, modifier, base)
    } else if isIsPrime(op.CalcOp) {
        success = op_IS_PRIME(res, BN0, BN1, BN2, direct)
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

//export Golang_Cryptofuzz_OpECC_Point_Add
func Golang_Cryptofuzz_OpECC_Point_Add(in []byte) {
    resetResult()

    var op OpECC_Point_Add
    unmarshal(in, &op)

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    b_x := decodeBignum(op.B_x)
    b_y := decodeBignum(op.B_y)

    if curve.IsOnCurve(b_x, b_y) == false {
        return
    }

    double := false

    if len(op.Modifier) >= 1 {
        if op.Modifier[0] & 1 == 1 {
            if a_x.Cmp(b_x) == 0 && a_y.Cmp(b_y) == 0 {
                double = true
            }
        }
    }

    var rx, ry *big.Int

    if double == false {
        rx, ry = curve.Add(a_x, a_y, b_x, b_y)
    } else {
        rx, ry = curve.Double(a_x, a_y)
    }

    res := make([]string, 2)
    res[0], res[1] = rx.String(), ry.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Golang_Cryptofuzz_OpECC_Point_Mul
func Golang_Cryptofuzz_OpECC_Point_Mul(in []byte) {
    resetResult()

    var op OpECC_Point_Mul
    unmarshal(in, &op)

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    b := decodeBignum(op.B).Bytes()

    rx, ry := curve.ScalarMult(a_x, a_y, b)
    res := make([]string, 2)
    res[0], res[1] = rx.String(), ry.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Golang_Cryptofuzz_OpECC_Point_Dbl
func Golang_Cryptofuzz_OpECC_Point_Dbl(in []byte) {
    resetResult()

    var op OpECC_Point_Dbl
    unmarshal(in, &op)

    curve, err := toCurve(op.CurveType)
    if err != nil {
        return
    }

    a_x := decodeBignum(op.A_x)
    a_y := decodeBignum(op.A_y)

    if curve.IsOnCurve(a_x, a_y) == false {
        return
    }

    rx, ry := curve.Double(a_x, a_y)
    res := make([]string, 2)
    res[0], res[1] = rx.String(), ry.String()

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
}

//export Golang_Cryptofuzz_OpDSA_Verify
func Golang_Cryptofuzz_OpDSA_Verify(in []byte) {
    resetResult()

    var op OpDSA_Verify
    unmarshal(in, &op)

    P := decodeBignum(op.P)
    Q := decodeBignum(op.Q)
    G := decodeBignum(op.G)
    Y := decodeBignum(op.Pub)
    parameters := dsa.Parameters{
            P: P,
            Q: Q,
            G: G,
    }
    pubKey := dsa.PublicKey{
        Parameters : parameters,
        Y: Y,
    }
    sigR := decodeBignum(op.Sig_R)
    sigS := decodeBignum(op.Sig_S)

    dsa.Verify(&pubKey, op.Cleartext, sigR, sigS)

    /* XXX */

    /*
    var res bool
    res = dsa.Verify(&pubKey, op.Cleartext, sigR, sigS)

    r2, err := json.Marshal(&res)
    if err != nil {
        panic("Cannot marshal to JSON")
    }

    result = r2
    */
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
