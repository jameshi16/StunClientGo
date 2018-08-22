# STUN Client Go
An implementation written by @jameshi16.

This is a partial implementation of the [RFC 5389](https://tools.ietf.org/html/rfc5389), albiet not fully. The implemented attributes are:
- MAPPED-ADDRESS
- XOR-MAPPED-ADDRESS

I'm too lazy to implement the rest of the attributes, because they weren't critical to my usage. This may get a full implementation in the future.

## Why
For UDP Hole Punching, which is a form of NAT Traversal. Useful for P2P connections.

## How to use
The package that contains the STUN Agent only has one exported function, which is `stun_c.RequestRemoteIPAndPort(conn *net.UDPConn, server *net.UDPAddr) (*net.UDPAddr, error)`.
The horrible (and inaccurate) name aside, this function will return the public IP and port of the `net.UDPConn` object passed into this function, using the STUN server provided in `server`.

The below is a wholesome (compilable) example snippet on how to use the function:
```go
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
```
The above code is also available in the file `test.go`.

## License
This is licensed under the **MIT License**.
