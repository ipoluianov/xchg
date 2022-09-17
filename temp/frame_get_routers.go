package temp

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

func XcGetRouters(ipAddress string, timeout time.Duration, address string) (result []*net.UDPAddr, err error) {
	result = make([]*net.UDPAddr, 0)

	addressBS := []byte(address)
	conn, err := net.ListenPacket("udp", ":")
	if err != nil {
		return
	}

	ipStr, portStr, err := net.SplitHostPort(ipAddress)
	if err != nil {
		return
	}

	var addr net.UDPAddr
	addr.IP = net.ParseIP(ipStr)
	if addr.IP == nil {
		err = errors.New("wrong IP address")
		return
	}
	portInt, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return
	}
	addr.Port = int(portInt)
	request := make([]byte, 8+len(addressBS))
	request[0] = 0x04
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
	buffer := make([]byte, 1024)
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

	if ((n - 8) % 32) != 0 {
		err = errors.New("wrong frame len")
		return
	}

	for i := 8; i < n; i += 32 {
		var udpAddr net.UDPAddr
		udpAddr.IP = buffer[i+2 : i+2+16]
		udpAddr.Port = int(binary.LittleEndian.Uint16(buffer[i+2+16:]))
		result = append(result, &udpAddr)
	}

	return
}
