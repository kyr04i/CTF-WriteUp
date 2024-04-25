package main

import (
	"os"
	"time"
	"plaidctf.com/pppvm/pppvm"
)

const CODE_SIZE = 0x4000
const TIMEOUT = 5 * time.Second

func main() {
	code := make([]byte, CODE_SIZE)
	totalRead := 0
	for totalRead < CODE_SIZE {
		n, err := os.Stdin.Read(code[totalRead:])
		if err != nil {
			panic(err.Error())
		}
		totalRead += n
	}
	vm := pppvm.NewVM()
	vm.Launch(code)
	time.Sleep(TIMEOUT)
}
