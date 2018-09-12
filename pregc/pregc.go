// +build !go1.1 go1.5

// Package pregc enables you to run code directly before the GC, while the world is stopped.
// Use this package with extreme caution, it accesses runtime functions that should not be used by normal code.
package pregc

import (
	// accessing unexported functions
	_ "unsafe"
)

//go:linkname runtimepoolcleanup runtime.poolcleanup
var runtimepoolcleanup func()

var (
	fs          []func()
	poolCleanup func()
)

func init() {
	poolCleanup = runtimepoolcleanup
	runtimepoolcleanup = execute
}

func execute() {

	for _, f := range fs {
		f()
	}

	if poolCleanup != nil {
		poolCleanup()
	}

}

// Add adds a function to the list of functions that is being executed before each GC. Do not call this concurrently!
// Do not call this concurrently with other functions of this package!
func Add(f func()) {
	fs = append(fs, f)
}

// Clear empties the list of functions that is being executed before each GC.
// Do not call this concurrently with other functions of this package!
func Clear() {
	fs = []func(){}
}
