package main

import (
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/common"
)

import "C"

//export Geth_ModExp_RequiredGas
func Geth_ModExp_RequiredGas(data []byte) uint64 {
	modexp := vm.PrecompiledContractsBerlin[common.BytesToAddress([]byte{5})]
	return modexp.RequiredGas(data)
}

func main() { }
