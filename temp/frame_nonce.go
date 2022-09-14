package temp

import (
	"errors"
	"net"
	"strconv"
	"time"
)

func XchgNonce(ipAddress string, timeout time.Duration) (nonce []byte, err error) {
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
	request := make([]byte, 8)
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

	if buffer[1] != 0 {
		err = errors.New("error code:" + strconv.FormatInt(int64(buffer[1]), 10))
		return
	}

	if n != 8+16 {
		err = errors.New("wrong response - size of frame")
		return
	}

	nonce = buffer[8:]
	return
}
