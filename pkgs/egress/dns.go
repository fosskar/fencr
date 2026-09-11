package main

import (
	"log"
	"net"
)

// every A query is answered with the bridge address, so every tls
// connection the guest opens lands here and the client hello names the real
// destination; everything else gets an empty answer
func serveDNS(conn net.PacketConn, answer net.IP) {
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
		if _, err := conn.WriteTo(reply, peer); err != nil {
			continue
		}
	}
}

func answerA(query []byte, answer net.IP) []byte {
	if len(query) < 12 || query[2]&0x80 != 0 {
		return nil
	}
	at := 12
	for at < len(query) {
		label := int(query[at])
		if label == 0 {
			at++
			break
		}
		at += 1 + label
	}
	if at+4 > len(query) {
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
