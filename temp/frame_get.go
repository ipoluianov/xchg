package temp

import (
	"errors"
	"net"
	"strconv"
	"time"
)

func XcGet(ipAddress string, timeout time.Duration, address string) (data []byte, err error) {
	addressBS := []byte(address)
	conn, err := net.ListenPacket("udp", ":")
	if err != nil {
		return
	}
	var addr net.UDPAddr
	addr.IP = net.ParseIP(ipAddress)
	if addr.IP == nil {
		err = errors.New("wrong IP address")
		return
	}
	addr.Port = 8484
	request := make([]byte, 8+len(addressBS))
	request[0] = 0x03
	copy(request[8:], addressBS)
	var n int
	n, err = conn.WriteTo(request, &addr)
	if err != nil {
		return
	}
	if n != len(request) {
		err = errors.New("data sent partially")
		return
	}
	buffer := make([]byte, 16)
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	n, _, err = conn.ReadFrom(buffer)
	if err != nil {
		return
	}

	if n < 8 {
		err = errors.New("wrong response - size of frame")
		return
	}

	if buffer[1] != 0 {
		err = errors.New("error code:" + strconv.FormatInt(int64(buffer[1]), 10))
		return
	}

	receivedAddr := ""
	data = nil

	for i := 8; i < n; i++ {
		if buffer[i] == '=' {
			receivedAddr = string(buffer[8:i])
			data = buffer[i+1 : n]
			break
		}
	}

	if receivedAddr != address {
		err = errors.New("wrong received address")
	}

	if data == nil {
		err = errors.New("no data in response")
	}

	return
}
