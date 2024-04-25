package pppvm

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

const MAX_STACK_SIZE = 256
const INBOX_BUFFER_SIZE = 16

var BOOL_TO_UINT64 = map[bool]uint64{false: 0, true: 1}

const (
	OP_NOP = 0x00

	OP_PUSH = 0x01
	OP_POP  = 0x02
	OP_DUP  = 0x03
	OP_SWAP = 0x04

	OP_ADD = 0x10
	OP_SUB = 0x11
	OP_MUL = 0x12
	OP_DIV = 0x13
	OP_MOD = 0x14

	OP_EQ     = 0x20
	OP_LT     = 0x21
	OP_GT     = 0x22
	OP_ISZERO = 0x23

	OP_JMP      = 0x30
	OP_JUMPIF   = 0x31
	OP_JMPREL   = 0x32
	OP_JMPRELIF = 0x33

	OP_RET   = 0x80
	OP_ERR   = 0x81
	OP_SLEEP = 0x82
	OP_DUMP  = 0x83

	OP_ID     = 0xf0
	OP_RECV   = 0xf1
	OP_SEND   = 0xf2
	OP_DELETE = 0xf3
	OP_LAUNCH = 0xfd
	OP_RESET  = 0xfe
	OP_JOIN   = 0xff
)

type Message struct {
	From Id
	Data []uint64
}

type Thread struct {
	vm     *VM
	id     Id
	code   []byte
	stack  []uint64
	pc     uint64
	inbox  chan *Message
	status Status
}

func NewThread(vm *VM, id Id, code []byte) *Thread {
	t := &Thread{
		vm:    vm,
		id:    id,
		code:  code,
		stack: make([]uint64, 0, MAX_STACK_SIZE),
		pc:    0,
		inbox: make(chan *Message, INBOX_BUFFER_SIZE),
	}
	t.status = Running(t, 0, nil)
	return t
}

func (t *Thread) push(value uint64) error {
	if len(t.stack) >= MAX_STACK_SIZE {
		return errors.New("stack overflow")
	}
	t.stack = append(t.stack, value)
	return nil
}

func (t *Thread) pushSlice(values []uint64) error {
	if len(t.stack)+len(values) > MAX_STACK_SIZE {
		return errors.New("stack overflow")
	}
	if len(t.stack) == 0 {
		t.stack = values
	} else {
		t.stack = append(t.stack, values...)
	}
	return nil
}

func (t *Thread) peek(offset int) (uint64, error) {
	if len(t.stack) <= offset {
		return 0, errors.New("stack underflow")
	}
	return t.stack[len(t.stack)-1-offset], nil
}

func (t *Thread) peekRange(count int) ([]uint64, error) {
	if len(t.stack) < count {
		return nil, errors.New("stack underflow")
	}
	return t.stack[len(t.stack)-count:], nil
}

func (t *Thread) pop() (uint64, error) {
	value, err := t.peek(0)
	if err != nil {
		return value, err
	}
	t.stack = t.stack[:len(t.stack)-1]
	return value, nil
}

func (t *Thread) swap(offset int) error {
	if len(t.stack) <= offset {
		return errors.New("stack underflow")
	}
	idx := len(t.stack) - 1 - offset
	tmp := t.stack[idx+offset]
	t.stack[idx+offset] = t.stack[idx]
	t.stack[idx] = tmp
	return nil
}

func (t *Thread) step() error {
	if t.pc >= uint64(len(t.code)) {
		return errors.New("PC out of bounds")
	}
	switch t.code[t.pc] {
	case OP_NOP:
		t.pc += 1
		return nil
	case OP_PUSH:
		if t.pc+9 > uint64(len(t.code)) {
			return errors.New("Invalid PUSH instruction")
		}
		value := binary.LittleEndian.Uint64(t.code[t.pc+1 : t.pc+9])
		t.pc += 9
		return t.push(value)
	case OP_POP:
		t.pc += 1
		_, err := t.pop()
		return err
	case OP_DUP:
		if t.pc+2 > uint64(len(t.code)) {
			return errors.New("Invalid DUP instruction")
		}
		off := int(t.code[t.pc+1])
		value, err := t.peek(off)
		if err != nil {
			return err
		}
		t.pc += 2
		return errors.Join(err, t.push(value))
	case OP_SWAP:
		if t.pc+2 > uint64(len(t.code)) {
			return errors.New("Invalid SWAP instruction")
		}
		off := int(t.code[t.pc+1])
		t.pc += 2
		return t.swap(off)
	case OP_ADD:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(lhs+rhs))
	case OP_SUB:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(lhs-rhs))
	case OP_MUL:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(lhs*rhs))
	case OP_DIV:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		if rhs == 0 && rerr != nil {
			return errors.New("Division by zero")
		}
		return errors.Join(lerr, rerr, t.push(lhs/rhs))
	case OP_MOD:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		if rhs == 0 && rerr != nil {
			return errors.New("Division by zero")
		}
		return errors.Join(lerr, rerr, t.push(lhs%rhs))
	case OP_EQ:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(BOOL_TO_UINT64[lhs == rhs]))
	case OP_LT:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(BOOL_TO_UINT64[lhs < rhs]))
	case OP_GT:
		t.pc += 1
		lhs, lerr := t.pop()
		rhs, rerr := t.pop()
		return errors.Join(lerr, rerr, t.push(BOOL_TO_UINT64[lhs > rhs]))
	case OP_ISZERO:
		t.pc += 1
		v, err := t.pop()
		return errors.Join(err, t.push(BOOL_TO_UINT64[v == 0]))
	case OP_JMP:
		dst, err := t.pop()
		t.pc = dst
		return err
	case OP_JUMPIF:
		dst, derr := t.pop()
		cond, cerr := t.pop()
		if cond != 0 {
			t.pc = dst
		} else {
			t.pc += 1
		}
		return errors.Join(derr, cerr)
	case OP_JMPREL:
		if t.pc+3 > uint64(len(t.code)) {
			return errors.New("Invalid JMPREL instruction")
		}
		off := uint64(int64(int16(binary.LittleEndian.Uint16(t.code[t.pc+1 : t.pc+3]))))
		t.pc += off
		return nil
	case OP_JMPRELIF:
		if t.pc+3 > uint64(len(t.code)) {
			return errors.New("Invalid JMPRELIF instruction")
		}
		off := uint64(int64(int16(binary.LittleEndian.Uint16(t.code[t.pc+1 : t.pc+3]))))
		cond, err := t.pop()
		if err != nil {
			return err
		}
		if cond != 0 {
			t.pc += off
		} else {
			t.pc += 3
		}
		return nil
	case OP_RET:
		t.pc += 1
		length, err := t.pop()
		data, err := t.peekRange(int(length))
		if err != nil {
			return err
		}
		t.status = Returned(data)
		return err
	case OP_ERR:
		t.pc += 1
		return errors.New("OP_ERR")
	case OP_SLEEP:
		t.pc += 1
		ms, err := t.pop()
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return nil
	case OP_DUMP:
		t.pc += 1
		t.Dump()
		return nil
	case OP_ID:
		t.pc += 1
		return t.push(uint64(t.id))
	case OP_RECV:
		t.pc += 1
		msg := <-t.inbox
		return errors.Join(t.pushSlice(msg.Data), t.push(uint64(len(msg.Data))), t.push(uint64(msg.From)))
	case OP_SEND:
		t.pc += 1
		dst, err := t.pop()
		if err != nil {
			return err
		}
		length, err := t.pop()
		if err != nil {
			return err
		}
		data := make([]uint64, length)
		s, err := t.peekRange(int(length))
		if err != nil {
			return err
		}
		copy(data, s) // 
		if peer := t.vm.Thread(Id(dst)); peer != nil {
			peer.SendMessage(&Message{
				From: t.id,
				Data: data,
			})
			return nil
		} else {
			return errors.New("Invalid destination")
		}
	case OP_DELETE:
		t.pc += 1
		id, err := t.pop()
		if err != nil {
			return err
		}
		t.vm.Delete(Id(id))
		return nil
	case OP_LAUNCH:
		t.pc += 1
		start, serr := t.pop()
		end, eerr := t.pop()
		max := uint64(len(t.code))
		if start > max || end > max || start > end {
			return errors.New("Invalid code range")
		}
		code := t.code[start:end]
		id, err := t.vm.Launch(code)
		return errors.Join(serr, eerr, err, t.push(uint64(id)))
	case OP_RESET:
		t.pc += 1
		id, err := t.pop()
		if err != nil {
			return err
		}
		if peer := t.vm.Thread(Id(id)); peer != nil {
			peer.MaybeReset()
			return nil
		} else {
			return errors.New("Invalid destination")
		}
	case OP_JOIN:
		t.pc += 1
		id, err := t.pop()
		if err != nil {
			return err
		}
		if peer := t.vm.Thread(Id(id)); peer != nil {
			status := peer.status
			for status.Running() {
				status = peer.status
			}
			result := status.Result()
			err := status.Error()
			if err != nil {
				return t.push(1)
			}
			return errors.Join(t.pushSlice(result), t.push(uint64(len(result))), t.push(0))
		} else {
			return errors.New("Invalid destination")
		}
	default:
		return errors.New("Invalid instruction")
	}
}

func (t *Thread) Dump() {
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(w, "-------------- Thread %d DUMP --------------\n", t.id)
	fmt.Fprintf(w, "status = %s\n", t.status)
	fmt.Fprintf(w, "pc = %d\n", t.pc)
	fmt.Fprintf(w, "stack: len=%d  cap=%d\n", len(t.stack), cap(t.stack))
	for i, v := range t.stack {
		fmt.Fprintf(w, " [%d] = %d\n", i, v)
	}
	fmt.Fprintf(w, "------------------------------------------\n")
	w.Flush()
}

func (t *Thread) SendMessage(msg *Message) {
	t.inbox <- msg
}

func (t *Thread) Run() {
	for t.status.Running() {
		err := t.step()
		if err != nil {
			t.status = Errored(err)
		}
		if r, ok := t.status.(running); ok {
			t.status = Running(t, r.steps+1, r.lastErr)
		}
	}
}

func (t *Thread) MaybeReset() {
	if t.status.Error() != nil {
		t.status = Running(t, 0, t.status.Error())
		go t.Run()
	}
}
