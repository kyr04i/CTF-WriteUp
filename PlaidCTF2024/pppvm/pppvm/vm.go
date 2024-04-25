package pppvm

import (
	"errors"
	"sync"
)

type Id uint64

const HOST_ID Id = Id(0)
const MAX_THREADS = 16

type VM struct {
	mu      sync.Mutex
	lastId  Id
	threads map[Id]*Thread
}

func NewVM() *VM {
	return &VM{
		lastId:  HOST_ID,
		threads: make(map[Id]*Thread),
	}
}

func (vm *VM) Launch(code []byte) (Id, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if len(vm.threads) >= MAX_THREADS {
		return Id(0), errors.New("Too many threads")
	}

	vm.lastId += 1
	id := vm.lastId
	thread := NewThread(vm, id, code)
	vm.threads[id] = thread

	go thread.Run()
	return id, nil
}

func (vm *VM) Thread(id Id) *Thread {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	t, _ := vm.threads[id]
	return t
}

func (vm *VM) Delete(id Id) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	delete(vm.threads, id)
}
