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
    bn, ok := new(big.Int).SetString(s, 10)
    if ok == false {
        panic("Cannot decode bignum")
    }
    return bn
}

func toCurve(curveType uint64) (elliptic.Curve, error) {
    if issecp224k1(curveType) {
        return elliptic.P224(), nil
    } else if issecp256k1(curveType) {
        return elliptic.P256(), nil
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

    privateKey := new(ecdsa.PrivateKey)
    privBN := decodeBignum(op.Priv)
    privateKey.D = privBN
    privateKey.PublicKey.Curve = curve

    privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privBN.Bytes())

    /* TODO set result */
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
