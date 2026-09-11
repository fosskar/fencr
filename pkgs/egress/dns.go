package main

import (
	"io"
	"log"
	"net"
	"time"
)

// one vm's share of the host resolver. a guest that asks faster than the
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
// speaks to the resolver itself: this unit is its one client
func forwardDNS(conn net.PacketConn, resolver string) {
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
			relayQuery(conn, peer, query, resolver)
		}()
	}
}

func relayQuery(conn net.PacketConn, peer net.Addr, query []byte, resolver string) {
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
	_, _ = conn.WriteTo(reply[:n], peer)
}

// a truncated udp answer sends the guest to tcp, so that road has to exist
// too; the bytes are relayed unread
func forwardDNSStream(listener net.Listener, resolver string) {
	slots := make(chan struct{}, maxQueries)
	for {
		conn, err := listener.Accept()
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
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(conn, upstream)
				close(done)
			}()
			_, _ = io.Copy(upstream, conn)
			<-done
		}()
	}
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
