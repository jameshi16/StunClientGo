package stun_c

import (
	"bytes"
	"crypto/rand" // Recommendation to use a crypto-secure hash
	"encoding/binary"
	"errors"
	"io"
	"net"
	"fmt"
)

/* Constants for usage by caller */
const MAGIC_COOKIE int32 = 0x2112A442

// RFC 5389 specifications, only the binding method exists (below constants are for the binding method only)
const REQUEST int16 = 0x0001
const INDICATION int16 = 0x0010
const SUCCESS_RESPONSE int16 = 0x0101
const ERROR_RESPONSE int16 = 0x0110

// RFC 5389 specify that transaction ID is 96 bits
const trans_id_size int8 = 96

// RFC 5389 specified comprehension-required range (0x0000 ~ 0x7FFF)
const MAPPED_ADDRESS int16 = 0x0001
const USERNAME int16 = 0x0006
const MESSAGE_INTEGRITY int16 = 0x0008
const ERROR_CODE int16 = 0x0009
const UNKNOWN_ATTRIBUTES int16 = 0x000A
const REALM int16 = 0x0014
const NONCE int16 = 0x0015
const XOR_MAPPED_ADDRESS int16 = 0x0020

// Error Structures
type Gen_Random_Error struct {}
type Make_Header_Error struct {}
type Message_Send_Error struct {}
type Not_Success_Response struct {
	header, body []byte
}
type Unknown_Transaction_Id struct {
	their_id, our_id []byte
}

func (e *Gen_Random_Error) Error() string {
	return "STUN Client: Cannot generate random hash."
}

func (e *Make_Header_Error) Error() string {
	return "STUN Client: Unable to successfully make message header."
}

func (e *Message_Send_Error) Error() string {
	return "STUN Client: Unable to send the message."
}

func (e *Not_Success_Response) Error() string {
	return fmt.Sprintf("STUN Client: There was not a success response. Concatenated packets recieved: 0x%x%x", e.header, e.body)
}

func (e *Unknown_Transaction_Id) Error() string {
	return fmt.Sprintf("STUN Client: Unknown transaction ID. Our ID: %x, Their ID: %x", e.our_id, e.their_id)
}


// Helper functions
func makeHeader(message_type int16, message_length int16, magic_cookie int32, transaction_id []byte) ([]byte, error) {
	buf := new (bytes.Buffer)

	// Encapsulate header information in a interface
	var data = []interface{}{
		message_type,
		message_length,
		magic_cookie,
		transaction_id,
	}

	for _, v := range data {
		err := binary.Write(buf, binary.BigEndian, v) //writes all the values into the buffer
		if err != nil {
			return nil, &Make_Header_Error{}
		}
	}

	return buf.Bytes(), nil
}

func getSingleAttribute(body []byte) (int16, int16, []byte, int, error) {
	if (len(body) == 0) {
		return 0, 0, nil, 0, errors.New("Cannot parse empty body.")
	}

	// Peek at the first and second 16 bits of the STUN attributes
	type_length := struct {
		Attr_type, Attr_len int16
	} {0, 0}

	err := binary.Read(bytes.NewBuffer(body), binary.BigEndian, &type_length)
	if (err != nil) {
		return 0, 0, nil, 0, err
	}

	// Create a buffer based on what we peeked
	value := make([]byte, type_length.Attr_len)
	copy(value, body[4 : 4 + type_length.Attr_len])

	return type_length.Attr_type, type_length.Attr_len, value, 4 + int(type_length.Attr_len), nil
}

func sendMessage(conn *net.UDPConn, server *net.UDPAddr, header []byte, body []byte) error {
	if (len(header) == 0) {
		return &Message_Send_Error{}
	}

	message := new (bytes.Buffer)

	_, err := message.Write(header) //writes the header
	if (err != nil) {
		return err
	}

	_, err = message.Write(body) //writes the body
	if (err != nil) {
		return err
	}

	msg := message.Bytes()
	size := message.Len()

	for size != 0 { //send entire message fully
		n, err := conn.WriteToUDP(msg, server)
		if (err != nil) {
			 return err
		}
		msg = msg[n : cap(msg)] //resizes the slice
		size -= n
	}
	return nil
}

//Will XOR the first byte slice
func xor_bytes(one []byte, two []byte) []byte {
	n := len(one)
	if n > len(two) {
		n = len(two)
	} //gets the minimum number of bytes of the two

	for i := 0; i < n; i++ {
		one[i] ^= two[i]
	}

	return one
}

func get_addr_XOR(attribute, transaction_id []byte) (*net.UDPAddr, error) {
	if len(attribute) == 0 {
		return nil, errors.New("STUN Client: Empty attribute recieved")
	}

	var data struct {
		Garbage, Family uint8
		XPort uint16
	}

	err := binary.Read(bytes.NewBuffer(attribute), binary.BigEndian, &data)
	if (err != nil) {
		return nil, err
	}

	//Port will always be the same regardless of family, so we compute that first
	port := data.XPort ^ uint16(MAGIC_COOKIE >> 16)
	buf := new (bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, MAGIC_COOKIE)
	if (err != nil) {
		return nil, err
	}
	magic_cookie := buf.Bytes()
	XAddress := attribute[4:] //the IPv4/6 XOR'd address

	//Switch based on family
	switch data.Family {
		case 0x01: //IPv4
			hostUdpAddr := new (net.UDPAddr)
			hostUdpAddr.IP = xor_bytes(XAddress, magic_cookie)
			hostUdpAddr.Port = int(port)
			return hostUdpAddr, nil

		case 0x02: //IPv6
			toXor := append(magic_cookie, transaction_id...) //concatenate magic cookie with transaction id
			hostUdpAddr := new (net.UDPAddr)
			hostUdpAddr.IP = xor_bytes(XAddress, toXor)
			hostUdpAddr.Port = int(port)
			return hostUdpAddr, nil
	}

	return nil, nil
}

func get_addr(attribute []byte) (*net.UDPAddr, error) { //WARNING: Untested
	if len(attribute) == 0 {
		return nil, errors.New("STUN Client: Empty attribute recieved")
	}

	var data struct {
		Garbage, Family uint8
		Port uint16
	}

	err := binary.Read(bytes.NewBuffer(attribute), binary.BigEndian, &data)
	if (err != nil) {
		return nil, err
	}

	//Doesn't matter what family, everything from attribute[4:] onwards is either a IPv4 or IPv6 address in byte form
	hostUdpAddr := new (net.UDPAddr)
	hostUdpAddr.IP = attribute[4:]
	hostUdpAddr.Port = int(data.Port)
	return hostUdpAddr, nil
}

func recvMessage(conn *net.UDPConn, transaction_id []byte) (*net.UDPAddr, error) {
	packet := make([]byte, 1280) // RFC 5389: Allocate enough for IPv6 packets too

	for n := 0; n == 0; {
		n, _, err := conn.ReadFromUDP(packet)
		if (err != nil) {
			return nil, err
		}

		if n > 0 {
			break
		}
	} //all data acquired 

	// Define the two different sections of the packet
	header := packet[0:20]
	body := packet[20:]

	// Read data from the header
	var data struct {
		Message_type, Message_length int16
		Magic_cookie int32
		Transaction_id [12]byte
	}

	err := binary.Read(bytes.NewBuffer(header), binary.BigEndian, &data)
	if (err != nil && err != io.EOF) {
		return nil, err
	}

	// Restrict body's length
	body = body[0:data.Message_length]

	// Use logic to determine IP address & Port
	if data.Message_type != SUCCESS_RESPONSE {
		return nil, &Not_Success_Response{header, body}
	}

	if !bytes.Equal(data.Transaction_id[0:12], transaction_id) {
		return nil, &Unknown_Transaction_Id{data.Transaction_id[0:12], transaction_id}
	}

	// Slowly read all the attributes
	bytes_read := 0
	for bytes_read < int(data.Message_length) {
		attr_type, attr_size, attr_value, r, err := getSingleAttribute(body)

		bytes_read += r
		body = body[attr_size:]

		if err != nil {
			return nil, err
		}

		// Parse comprehension required attributes
		switch (attr_type) {
			case MAPPED_ADDRESS:
				return get_addr(attr_value)

			case XOR_MAPPED_ADDRESS:
				return get_addr_XOR(attr_value, transaction_id)

			/* Not implemented, too lazy */
			case USERNAME:
				break

			case MESSAGE_INTEGRITY:
				break

			case ERROR_CODE:
				break

			case REALM:
				break

			case NONCE:
				break
		}

	}

	return nil, nil
}

// Exported functions
func RequestRemoteIPAndPort(conn *net.UDPConn, server *net.UDPAddr) (*net.UDPAddr, error) {
	// Ensure that conn and server are not nil
	if conn == nil || server == nil {
		return nil, &Gen_Random_Error{}
	}

	request_header := make([]byte, 20)
	secureRandomNumber := make([]byte, trans_id_size / 8)

	// Obtain cryptographically safe hash as Transaction ID
	_, err := rand.Read(secureRandomNumber)
	if err != nil {
		return nil, &Gen_Random_Error{}
	}

	// Build the request header
	request_header, err = makeHeader(REQUEST, 0, MAGIC_COOKIE, secureRandomNumber)
	if (err != nil) {
		return nil, err
	}

	// Send the request
	err = sendMessage(conn, server, request_header, nil)
	if (err != nil) {
		return nil, err
	}

	// Get the response
	addr, err := recvMessage(conn, secureRandomNumber)
	if (err != nil) {
		return nil, err
	}

	return addr, nil
}
