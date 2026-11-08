//go:build !unix

package mdns

import (
	"context"
	"net"
	"net/netip"
	"strconv"
)

func listenMulticast(network string, group netip.Addr) (net.PacketConn, error) {
	addr := "0.0.0.0"
	if network == "udp6" {
		addr = "::"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), network, net.JoinHostPort(addr, strconv.Itoa(port)))
}
