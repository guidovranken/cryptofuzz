package main

import (
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
    "encoding/json"
    "bytes"
    "encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/rawdb"
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

//export Geth_GetResult
func Geth_GetResult() *C.char {
    return C.CString(string(result))
}

func setResult(r ByteSlice) {
    r2, err := json.Marshal(&r)
    if err != nil {
        panic("Cannot marshal to JSON")
    }
    result = r2
}

//export Geth_ModExp
func Geth_ModExp(input []byte, gas uint64) {
    resetResult()

    statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	ret, _, err := runtime.Call(common.BytesToAddress([]byte{0x05}), input, &runtime.Config{
        EVMConfig: vm.Config{
            Debug:  false,
        },
		State:       statedb,
		GasLimit: gas,
	})

    if err == nil {
        setResult(ret)
    }
}

func main() { }
