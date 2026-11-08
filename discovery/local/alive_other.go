//go:build !unix

package local

// alive cannot cheaply check processes here; clients verify liveness by
// fetching the descriptor instead.
func alive(pid int) bool { return true }
