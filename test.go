package main

import (
	"fmt"
	"net"
	"./stun_c"
)

func main() {
	server, err := net.ResolveUDPAddr("udp", "stun.l.google.com:19302") //by the way, "udpv6" works too
	if (err != nil) {
		fmt.Println(err)
		return
	}

	local_socket, err := net.ListenUDP("udp", nil)
	if (err != nil) {
		fmt.Println(err)
		return
	}

	remote_addr, err := stun_c.RequestRemoteIPAndPort(local_socket, server)
	if (err != nil) {
		fmt.Println(err)
		return
	}

	fmt.Printf("Local socket: %s, Remote socket: %s\n", local_socket.LocalAddr(), remote_addr)
	return
}
