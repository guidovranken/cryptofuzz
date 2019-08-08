package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
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
)

import "C"

type ByteSlice []byte

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

func slice(modifier ByteSlice, in ByteSlice) []ByteSlice {
    ret := make([]ByteSlice, 0)
    modifierPos := 0
    pos := uint32(0)

    for uint32(len(in)) - pos > 0 {
        curLength := uint32(len(in)) - pos

        if modifierPos + 4 < len(modifier) {
            curLength = binary.LittleEndian.Uint32(modifier[modifierPos:modifierPos+4]) % (curLength+1)
            modifierPos += 4
        }

        ret = append(ret, in[pos:pos+curLength])
        pos += curLength
    }

    return ret
}

func digest(modifier ByteSlice, cleartext ByteSlice, h hash.Hash) {
    slices := slice(modifier, cleartext)
    for i := 0; i < len(slices); i++ {
        h.Write(slices[i])
    }

    res := ByteSlice(h.Sum(nil))

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
    unmarshal(in, op)

    h, err := toHashInstance(op.DigestType)
    if err != nil {
        return
    }

    digest(op.Modifier, op.Cleartext, h)
}

//export Golang_Cryptofuzz_OpHMAC
func Golang_Cryptofuzz_OpHMAC(in []byte) {
    resetResult()

    var op OpHMAC
    unmarshal(in, op)

    hash, err := toHashFunc(op.DigestType)
    if err != nil {
        return
    }

    hmac := hmac.New(hash, op.Cipher.Key)

    slices := slice(op.Modifier, op.Cleartext)

    for i := 0; i < len(slices); i++ {
        hmac.Write(slices[i])
    }

    mac := hmac.Sum(nil)

    setResult(mac)
}

//export Golang_Cryptofuzz_OpKDF_SCRYPT
func Golang_Cryptofuzz_OpKDF_SCRYPT(in []byte) {
    resetResult()

    var op OpKDF_SCRYPT
    unmarshal(in, op)

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
    unmarshal(in, op)

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
    unmarshal(in, op)

    h, err := toHashFunc(op.DigestType)
    if err != nil {
        return
    }

    key := pbkdf2.Key(op.Password, op.Salt, int(op.KeySize), int(op.Iterations), h)

    setResult(key)
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
