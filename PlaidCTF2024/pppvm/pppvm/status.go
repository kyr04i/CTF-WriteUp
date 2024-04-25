package pppvm

import (
	"bufio"
	"bytes"
	"fmt"
)

type Status interface {
	fmt.Stringer
	Running() bool
	Error() error
	Result() []uint64
}

type running struct {
	t       *Thread
	steps   uint64
	lastErr error
}

func Running(t *Thread, steps uint64, lastErr error) running { return running{t, steps, lastErr} }
func (running) Running() bool                                { return true }
func (running) Error() error                                 { return nil }
func (running) Result() []uint64                             { return nil }
func (r running) String() string {
	res := fmt.Sprintf("running: step %d | pending msgs %d", r.steps, len(r.t.inbox))
	if r.lastErr != nil {
		res = fmt.Sprintf("%s (reset from err: %s)", res, r.lastErr.Error())
	}
	return res
}

type errored struct {
	err error
}

func Errored(err error) errored    { return errored{err} }
func (e errored) Running() bool    { return false }
func (e errored) Error() error     { return e.err }
func (e errored) Result() []uint64 { return nil }
func (e errored) String() string {
	errmsg := "(nil)"
	if e.err != nil {
		errmsg = e.err.Error()
	}
	return fmt.Sprintf("err: %s", errmsg)
}

type returned struct {
	data []uint64
	buf  string
}

func Returned(data []uint64) returned { return returned{data, ""} }
func (r returned) Running() bool      { return false }
func (r returned) Error() error       { return nil }
func (r returned) Result() []uint64   { return r.data }
func (r returned) String() string {
	if r.buf == "" {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		fmt.Fprint(w, "result: [")
		for i, v := range r.data {
			fmt.Fprintf(w, "%d", v)
			if i != len(r.data)-1 {
				fmt.Fprint(w, ", ")
			}
		}
		fmt.Fprint(w, "]")
		w.Flush()
		r.buf = buf.String()
	}
	return r.buf
}
