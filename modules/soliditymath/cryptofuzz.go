package main

import (
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
    "encoding/json"
    "bytes"
    "encoding/hex"
)

import "C"

type ByteSlice []byte
type Type uint64

func (b *ByteSlice) MarshalJSON() ([]byte, error) {
    var buffer bytes.Buffer
    buffer.WriteString("\"")
    buffer.WriteString(hex.EncodeToString(*b))
    buffer.WriteString("\"")
    return buffer.Bytes(), nil
}

var result []byte

func resetResult() {
    result = []byte{}
}

//export SolidityMath_GetResult
func SolidityMath_GetResult() *C.char {
    return C.CString(string(result))
}

func setResult(r ByteSlice) {
    r2, err := json.Marshal(&r)
    if err != nil {
        panic("Cannot marshal to JSON")
    }
    result = r2
}

//export SolidityMath_Call
func SolidityMath_Call(contract []byte, calldata []byte, gas uint64) {
    resetResult()

	ret, _, err := runtime.Execute(contract, calldata, &runtime.Config{
        EVMConfig: vm.Config{
            Debug:  false,
        },
		GasLimit: gas,
	})

    if err == nil {
        setResult(ret)
    }
}

func main() { }
