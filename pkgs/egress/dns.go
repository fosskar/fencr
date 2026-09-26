package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// one sandbox's share of the host resolver. a guest that asks faster than the
// resolver answers loses its own queries, not the host's
const maxQueries = 256

// every A query is answered with the bridge address, so every tls
// connection the guest opens lands here and the client hello names the real
// destination; everything else gets an empty answer
func answerDNS(conn net.PacketConn, answer net.IP) {
	query := make([]byte, 512)
	for {
		n, peer, err := conn.ReadFrom(query)
		if err != nil {
			log.Printf("dns: %v", err)
			return
		}
		reply := answerA(query[:n], answer)
		if reply == nil {
			continue
		}
		// a reply that cannot be sent is that client's loss
		_, _ = conn.WriteTo(reply, peer)
	}
}

// with an open grant there is no name to judge and the guest needs real
// addresses, so the query is relayed to the host's stub. the guest never
// speaks to the resolver itself: this unit is its one client. the stub
// knows the host's names too, /etc/hosts, split dns, mdns, _gateway, so an
// answer is screened before the guest sees it
func forwardDNS(conn net.PacketConn, resolver string, private []netip.Prefix) {
	slots := make(chan struct{}, maxQueries)
	buffer := make([]byte, 4096)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("dns: %v", err)
			return
		}
		query := append([]byte(nil), buffer[:n]...)
		select {
		case slots <- struct{}{}:
		default:
			log.Printf("dns: %s dropped, %d queries already waiting", questionName(query), maxQueries)
			continue
		}
		go func() {
			defer func() { <-slots }()
			relayQuery(conn, peer, query, resolver, private)
		}()
	}
}

func relayQuery(conn net.PacketConn, peer net.Addr, query []byte, resolver string, private []netip.Prefix) {
	if reversesPrivate(query, private) {
		if refused := refusal(query); refused != nil {
			_, _ = conn.WriteTo(refused, peer)
		}
		return
	}
	upstream, err := net.DialTimeout("udp", resolver, 2*time.Second)
	if err != nil {
		log.Printf("dns: %v", err)
		return
	}
	defer upstream.Close()
	if err := upstream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if _, err := upstream.Write(query); err != nil {
		log.Printf("dns: %s: %v", questionName(query), err)
		return
	}
	reply := make([]byte, 4096)
	n, err := upstream.Read(reply)
	if err != nil {
		log.Printf("dns: %s: %v", questionName(query), err)
		return
	}
	if answer := screened(query, reply[:n], private); answer != nil {
		_, _ = conn.WriteTo(answer, peer)
	}
}

type dnsStream struct{ net.Conn }

func (conn dnsStream) Read(buffer []byte) (int, error) {
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return conn.Conn.Read(buffer)
}

func (conn dnsStream) Write(buffer []byte) (int, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	return conn.Conn.Write(buffer)
}

// a truncated udp answer sends the guest to tcp, so that road has to exist
// too, screened the same way: one message in, one answer out
func forwardDNSStream(listener *net.TCPListener, resolver string, private []netip.Prefix) {
	slots := make(chan struct{}, maxQueries)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("dns: %v", err)
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer conn.Close()
			upstream, err := net.DialTimeout("tcp", resolver, 2*time.Second)
			if err != nil {
				log.Printf("dns: %v", err)
				return
			}
			defer upstream.Close()
			relayStream(dnsStream{conn}, dnsStream{upstream}, private)
		}()
	}
}

func relayStream(guest, upstream io.ReadWriter, private []netip.Prefix) {
	for {
		query, err := readMessage(guest)
		if err != nil {
			return
		}
		if reversesPrivate(query, private) {
			refused := refusal(query)
			if refused == nil || writeMessage(guest, refused) != nil {
				return
			}
			continue
		}
		if writeMessage(upstream, query) != nil {
			return
		}
		reply, err := readMessage(upstream)
		if err != nil {
			return
		}
		answer := screened(query, reply, private)
		if answer == nil || writeMessage(guest, answer) != nil {
			return
		}
	}
}

func readMessage(conn io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, message); err != nil {
		return nil, err
	}
	return message, nil
}

func writeMessage(conn io.Writer, message []byte) error {
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(message)))
	_, err := conn.Write(append(framed, message...))
	return err
}

// the reply unless it names an address in a special-use range; then, or
// when it cannot be read, a refusal. whether the name exists still shows
func screened(query, reply []byte, private []netip.Prefix) []byte {
	if addresses, ok := answerAddresses(reply); ok {
		for _, address := range addresses {
			if withinPrefixes(private, address) {
				log.Printf("dns: %s refused: its answer is a special-use address", questionName(query))
				return refusal(query)
			}
		}
		return reply
	}
	log.Printf("dns: %s refused: its answer cannot be read", questionName(query))
	return refusal(query)
}

// REFUSED with the guest's own id and question, nothing else
func refusal(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	end := questionEnd(query)
	if end < 0 || end+4 > len(query) {
		return nil
	}
	reply := append([]byte(nil), query[:end+4]...)
	reply[2] = 0x80 | query[2]&0x79
	reply[3] = 0x80 | 5
	reply[4], reply[5] = 0, 1
	for at := 6; at < 12; at++ {
		reply[at] = 0
	}
	return reply
}

// netip, not net: a net.IPNet for ::ffff:0:0/96 contains every IPv4 address
func withinPrefixes(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// every A and AAAA in every section; false when the message does not parse
func answerAddresses(message []byte) ([]netip.Addr, bool) {
	if len(message) < 12 {
		return nil, false
	}
	count := func(at int) int { return int(binary.BigEndian.Uint16(message[at:])) }
	at := 12
	for range count(4) {
		end, ok := skipName(message, at)
		if !ok || end+4 > len(message) {
			return nil, false
		}
		at = end + 4
	}
	var addresses []netip.Addr
	for range count(6) + count(8) + count(10) {
		end, ok := skipName(message, at)
		if !ok || end+10 > len(message) {
			return nil, false
		}
		kind := binary.BigEndian.Uint16(message[end:])
		length := int(binary.BigEndian.Uint16(message[end+8:]))
		data := end + 10
		if data+length > len(message) {
			return nil, false
		}
		switch {
		case kind == 1 && length == net.IPv4len, kind == 28 && length == net.IPv6len:
			address, _ := netip.AddrFromSlice(message[data : data+length])
			addresses = append(addresses, address)
		}
		at = data + length
	}
	return addresses, true
}

// past a name, which may end in a pointer
func skipName(message []byte, at int) (int, bool) {
	for at < len(message) {
		label := int(message[at])
		switch {
		case label == 0:
			return at + 1, true
		case label&0xc0 == 0xc0:
			return at + 2, at+2 <= len(message)
		case label&0xc0 != 0:
			return 0, false
		}
		at += 1 + label
	}
	return 0, false
}

// a PTR lookup of a special-use address answers with the host's name for it
func reversesPrivate(query []byte, private []netip.Prefix) bool {
	end := questionEnd(query)
	if len(query) < 12 || end < 0 {
		return false
	}
	var labels []string
	for at := 12; at < end-1; at += 1 + int(query[at]) {
		if at+1+int(query[at]) > len(query) {
			return false
		}
		labels = append(labels, strings.ToLower(string(query[at+1:at+1+int(query[at])])))
	}
	network, reverse, readable := reverseNetwork(labels)
	if !reverse {
		return false
	}
	if !readable {
		return true
	}
	for _, blocked := range private {
		if blocked.Overlaps(network) {
			return true
		}
	}
	return false
}

// the network a reverse name covers; a name under a reverse zone that does
// not read as an address is refused
func reverseNetwork(labels []string) (network netip.Prefix, reverse, readable bool) {
	n := len(labels)
	switch {
	case n >= 2 && labels[n-2] == "in-addr" && labels[n-1] == "arpa":
		octets := labels[:n-2]
		if len(octets) > 4 {
			return network, true, false
		}
		var address [4]byte
		for at, label := range octets {
			value, err := strconv.Atoi(label)
			if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != label {
				return network, true, false
			}
			address[len(octets)-1-at] = byte(value)
		}
		return netip.PrefixFrom(netip.AddrFrom4(address), 8*len(octets)), true, true
	case n >= 2 && labels[n-2] == "ip6" && labels[n-1] == "arpa":
		nibbles := labels[:n-2]
		if len(nibbles) > 32 {
			return network, true, false
		}
		var address [16]byte
		for at, label := range nibbles {
			value, err := strconv.ParseUint(label, 16, 8)
			if err != nil || len(label) != 1 {
				return network, true, false
			}
			position := len(nibbles) - 1 - at
			address[position/2] |= byte(value) << (4 * (1 - position%2))
		}
		return netip.PrefixFrom(netip.AddrFrom16(address), 4*len(nibbles)), true, true
	}
	return network, false, false
}

func answerA(query []byte, answer net.IP) []byte {
	if len(query) < 12 || query[2]&0x80 != 0 {
		return nil
	}
	at := questionEnd(query)
	if at < 0 || at+4 > len(query) {
		return nil
	}
	question := query[12 : at+4]
	wantsA := question[len(question)-4] == 0 && question[len(question)-3] == 1

	reply := make([]byte, 0, len(query)+16)
	reply = append(reply, query[0], query[1])
	reply = append(reply, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
	reply = append(reply, question...)
	if wantsA {
		reply[7] = 1
		reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
		reply = append(reply, answer.To4()...)
	}
	return reply
}

func questionEnd(query []byte) int {
	at := 12
	for at < len(query) {
		label := int(query[at])
		if label == 0 {
			return at + 1
		}
		at += 1 + label
	}
	return -1
}

// only for the journal, where a dropped query is worth a name; a label the
// guest chose must not be able to forge a line
func questionName(query []byte) string {
	end := questionEnd(query)
	if len(query) < 12 || end < 0 {
		return "?"
	}
	name := make([]byte, 0, end-12)
	for at := 12; at < end-1; {
		label := int(query[at])
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, query[at+1:at+1+label]...)
		at += 1 + label
	}
	clean, err := hostName(name)
	if err != nil {
		return "?"
	}
	return clean
}
