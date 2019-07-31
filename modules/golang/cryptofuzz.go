package main

import (
    "bytes"
    "hash"
    "hash/crc32"
    "hash/adler32"
    "golang.org/x/crypto/md4"
    "crypto/md5"
    "golang.org/x/crypto/ripemd160"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "golang.org/x/crypto/blake2s"
    "golang.org/x/crypto/blake2b"
    "encoding/json"
    "encoding/hex"
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

var result []byte

func resetResult() {
    result = []byte{}
}

func setResult(r []byte) {
    result = r
}

//export Golang_Cryptofuzz_GetResult
func Golang_Cryptofuzz_GetResult() *C.char {
    return C.CString(string(result))
}

func digest(modifier ByteSlice, cleartext ByteSlice, h hash.Hash) {
    /* TODO use modifier */
    h.Write(cleartext)
    res := ByteSlice(h.Sum(nil))
    res2, err := json.Marshal(&res)
    if err != nil {
        panic("")
    }
    setResult(res2)
}

//export Golang_Cryptofuzz_OpDigest
func Golang_Cryptofuzz_OpDigest(in []byte) {
    resetResult()

    var op OpDigest
    err := json.Unmarshal(in, &op)
    if err != nil {
        return
    }

    if false {
    } else if isCRC32(op.DigestType) {
        digest(op.Modifier, op.Cleartext, crc32.NewIEEE())
    } else if isADLER32(op.DigestType) {
        digest(op.Modifier, op.Cleartext, adler32.New())
    } else if isMD4(op.DigestType) {
        digest(op.Modifier, op.Cleartext, md4.New())
    } else if isMD5(op.DigestType) {
        digest(op.Modifier, op.Cleartext, md5.New())
    } else if isRIPEMD160(op.DigestType) {
        digest(op.Modifier, op.Cleartext, ripemd160.New())
    } else if isSHA1(op.DigestType) {
        digest(op.Modifier, op.Cleartext, sha1.New())
    } else if isSHA256(op.DigestType) {
        digest(op.Modifier, op.Cleartext, sha256.New())
    } else if isSHA512(op.DigestType) {
        digest(op.Modifier, op.Cleartext, sha512.New())
    } else if isBLAKE2S128(op.DigestType) {
        h, err := blake2s.New128(nil)
        if err != nil {
            digest(op.Modifier, op.Cleartext, h)
        }
    } else if isBLAKE2S256(op.DigestType) {
        h, err := blake2s.New256(nil)
        if err != nil {
            digest(op.Modifier, op.Cleartext, h)
        }
    } else if isBLAKE2B256(op.DigestType) {
        h, err := blake2b.New256(nil)
        if err != nil {
            digest(op.Modifier, op.Cleartext, h)
        }
    } else if isBLAKE2B384(op.DigestType) {
        h, err := blake2b.New384(nil)
        if err != nil {
            digest(op.Modifier, op.Cleartext, h)
        }
    } else if isBLAKE2B512(op.DigestType) {
        h, err := blake2b.New512(nil)
        if err != nil {
            digest(op.Modifier, op.Cleartext, h)
        }
    }
}

func main() { }
