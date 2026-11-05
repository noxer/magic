package mdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Responder advertises one service until closed.
type Responder struct {
	svc    Service
	v4     *ipv4.PacketConn
	v6     *ipv6.PacketConn
	ifaces []net.Interface
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
}

// Advertise starts announcing svc on all multicast interfaces.
func Advertise(svc Service) (*Responder, error) {
	if svc.Host == "" {
		svc.Host, _ = os.Hostname()
	}
	r := &Responder{svc: svc, ifaces: multicastInterfaces()}
	if len(r.ifaces) == 0 {
		return nil, errors.New("mdns: no multicast interfaces")
	}
	var errs []error
	if c, err := listenMulticast("udp4", groupV4); err == nil {
		r.v4 = ipv4.NewPacketConn(c)
		r.v4.SetControlMessage(ipv4.FlagInterface, true)
		r.v4.SetMulticastTTL(255)
		r.v4.SetMulticastLoopback(true)
		joined := 0
		for i := range r.ifaces {
			if r.v4.JoinGroup(&r.ifaces[i], &net.UDPAddr{IP: groupV4.AsSlice()}) == nil {
				joined++
			}
		}
		if joined == 0 {
			c.Close()
			r.v4 = nil
			errs = append(errs, errors.New("mdns: could not join IPv4 group"))
		}
	} else {
		errs = append(errs, err)
	}
	if c, err := listenMulticast("udp6", groupV6); err == nil {
		r.v6 = ipv6.NewPacketConn(c)
		r.v6.SetControlMessage(ipv6.FlagInterface, true)
		r.v6.SetMulticastHopLimit(255)
		r.v6.SetMulticastLoopback(true)
		joined := 0
		for i := range r.ifaces {
			if r.v6.JoinGroup(&r.ifaces[i], &net.UDPAddr{IP: groupV6.AsSlice()}) == nil {
				joined++
			}
		}
		if joined == 0 {
			c.Close()
			r.v6 = nil
		}
	}
	if r.v4 == nil && r.v6 == nil {
		return nil, errors.Join(errs...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	if r.v4 != nil {
		r.wg.Add(1)
		go r.serve4()
	}
	if r.v6 != nil {
		r.wg.Add(1)
		go r.serve6()
	}
	r.wg.Add(1)
	go r.announce(ctx)
	return r, nil
}

func (r *Responder) announce(ctx context.Context) {
	defer r.wg.Done()
	delay := time.Second
	for i := 0; i < 3; i++ {
		r.broadcast(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// broadcast multicasts all records on every interface.
func (r *Responder) broadcast(goodbye bool) {
	for i := range r.ifaces {
		ifi := &r.ifaces[i]
		ptrs, svc, host := r.svc.records(interfaceAddrs(ifi), goodbye)
		answers := append(append(ptrs, svc...), host...)
		b, err := pack(0, true, nil, answers, nil)
		if err != nil {
			continue
		}
		if r.v4 != nil {
			r.v4.WriteTo(b, &ipv4.ControlMessage{IfIndex: ifi.Index}, &net.UDPAddr{IP: groupV4.AsSlice(), Port: port})
		}
		if r.v6 != nil {
			r.v6.WriteTo(b, &ipv6.ControlMessage{IfIndex: ifi.Index}, &net.UDPAddr{IP: groupV6.AsSlice(), Port: port, Zone: ifi.Name})
		}
	}
}

func (r *Responder) serve4() {
	defer r.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.v4.ReadFrom(buf)
		if err != nil {
			return
		}
		ifIndex := 0
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		r.handle(buf[:n], ifIndex, src.(*net.UDPAddr), func(b []byte, dst *net.UDPAddr) {
			r.v4.WriteTo(b, &ipv4.ControlMessage{IfIndex: ifIndex}, dst)
		}, &net.UDPAddr{IP: groupV4.AsSlice(), Port: port})
	}
}

func (r *Responder) serve6() {
	defer r.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.v6.ReadFrom(buf)
		if err != nil {
			return
		}
		ifIndex := 0
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		zone := ""
		if ifi, err := net.InterfaceByIndex(ifIndex); err == nil {
			zone = ifi.Name
		}
		r.handle(buf[:n], ifIndex, src.(*net.UDPAddr), func(b []byte, dst *net.UDPAddr) {
			r.v6.WriteTo(b, &ipv6.ControlMessage{IfIndex: ifIndex}, dst)
		}, &net.UDPAddr{IP: groupV6.AsSlice(), Port: port, Zone: zone})
	}
}

func (r *Responder) handle(pkt []byte, ifIndex int, src *net.UDPAddr, send func([]byte, *net.UDPAddr), group *net.UDPAddr) {
	var q dnsmessage.Message
	if err := q.Unpack(pkt); err != nil || q.Response || len(q.Questions) == 0 {
		return
	}
	var addrs []netip.Addr
	if ifi, err := net.InterfaceByIndex(ifIndex); err == nil {
		addrs = interfaceAddrs(ifi)
	} else {
		for i := range r.ifaces {
			addrs = append(addrs, interfaceAddrs(&r.ifaces[i])...)
		}
	}
	answers, additionals := r.svc.answer(&q, addrs)
	if answers == nil {
		return
	}
	legacy := src.Port != port
	unicast := legacy
	for _, qq := range q.Questions {
		if uint16(qq.Class)&unicastQ != 0 {
			unicast = true
		}
	}
	if legacy {
		// RFC 6762 6.7: echo ID and questions, no cache-flush bits, TTL <= 10.
		for _, rs := range [][]dnsmessage.Resource{answers, additionals} {
			for i := range rs {
				rs[i].Header.Class &^= cacheFlush
				if rs[i].Header.TTL > 10 {
					rs[i].Header.TTL = 10
				}
			}
		}
		qs := make([]dnsmessage.Question, len(q.Questions))
		for i, qq := range q.Questions {
			qq.Class &^= unicastQ
			qs[i] = qq
		}
		if b, err := pack(q.ID, true, qs, answers, additionals); err == nil {
			send(b, src)
		}
		return
	}
	b, err := pack(0, true, nil, answers, additionals)
	if err != nil {
		return
	}
	if unicast {
		send(b, src)
		return
	}
	time.Sleep(20*time.Millisecond + jitter(100*time.Millisecond)) // RFC 6762 6
	send(b, group)
}

// Close sends goodbye packets and stops the responder.
func (r *Responder) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.broadcast(true)
	if r.v4 != nil {
		r.v4.Close()
	}
	if r.v6 != nil {
		r.v6.Close()
	}
	r.wg.Wait()
	return nil
}
