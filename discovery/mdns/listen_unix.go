//go:build unix

package mdns

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenMulticast binds the mDNS port with address reuse so that the system
// mDNS daemon (Avahi, mDNSResponder) and other responders can coexist.
func listenMulticast(network string, group netip.Addr) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	addr := "0.0.0.0"
	if network == "udp6" {
		addr = "::"
	}
	return lc.ListenPacket(context.Background(), network, net.JoinHostPort(addr, strconv.Itoa(port)))
}
