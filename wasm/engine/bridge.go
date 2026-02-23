//go:build js && wasm

package main

import (
	"fmt"

	"syscall/js" // requires GOOS=js GOARCH=wasm; see //go:build constraint above
)

type handlerFunc func(input []byte) ([]byte, error)

// wrapHandler converts a Go handler into a js.Func that accepts a Uint8Array
// and returns a Uint8Array, or a {error: string} object on failure.
func wrapHandler(fn handlerFunc) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		output, err := safeInvoke(fn, args)
		if err != nil {
			return js.ValueOf(map[string]any{"error": err.Error()})
		}
		return bytesToJS(output)
	})
}

// safeInvoke runs the handler inside a recovery boundary so that any panic
// is converted to an error instead of killing the Go runtime.
func safeInvoke(fn handlerFunc, args []js.Value) (output []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine panic: %v", r)
		}
	}()

	if len(args) < 1 {
		return nil, fmt.Errorf("expected Uint8Array argument")
	}

	input := jsToBytes(args[0])
	return fn(input)
}

func jsToBytes(v js.Value) []byte {
	buf := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(buf, v)
	return buf
}

func bytesToJS(b []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

