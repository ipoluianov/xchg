package temp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/ipoluianov/xchg/xchg"
)

func XchgSet(conn net.PacketConn, ipAddress string, timeout time.Duration, privateKey *rsa.PrivateKey) (err error) {
	nonce, err := XchgNonce(ipAddress, timeout)
	if err != nil {
		return
	}

	var addr net.UDPAddr
	addr.IP = net.ParseIP(ipAddress)
	addr.Port = 8484

	data := make([]byte, 2)
	data[0] = 42
	data[1] = 84

	publicKeyBS := xchg.RSAPublicKeyToDer(&privateKey.PublicKey)

	request := make([]byte, 8+16+8+256+4+len(publicKeyBS)+len(data))

	request[0] = 0x02

	copy(request[8:], nonce)
	// copy(request[24:], salt) // TODO: salt

	hash := sha256.Sum256(request[8:32])
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return
	}
	copy(request[32:], signature)

	binary.LittleEndian.PutUint32(request[288:], uint32(len(publicKeyBS)))
	copy(request[292:], publicKeyBS)
	copy(request[292+len(publicKeyBS):], data)

	var n int
	n, err = conn.WriteTo(request, &addr)
	if err != nil {
		return
	}
	if n != len(request) {
		err = errors.New("data sent partially")
		return
	}

	buffer := make([]byte, 8)
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}

	n, _, err = conn.ReadFrom(buffer)
	if err != nil {
		return
	}

	if n != 8 {
		err = errors.New("wrong response - size of frame")
		return
	}

	if buffer[1] != 0 {
		err = errors.New("error code:" + strconv.FormatInt(int64(buffer[1]), 10))
	}

	return
}
