package xchg

import (
	"crypto/rsa"
	"errors"

	"github.com/ipoluianov/gomisc/crypt_tools"
)

type ClientConnection struct {
	edgeConnections map[string]*EdgeConnection

	aesKey    []byte
	sessionId uint64
	address   string
	authData  string
}

func NewClientConnection(address string, authData string) *ClientConnection {
	var c ClientConnection
	c.address = address
	c.edgeConnections = make(map[string]*EdgeConnection)
	privateKey := c.generateTempPrivateKey()
	eConn := NewEdgeConnection("localhost:8484", privateKey)
	c.edgeConnections["localhost:8484"] = eConn

	eConn.Start()
	return &c
}

func (c *ClientConnection) generateTempPrivateKey() *rsa.PrivateKey {
	privateKey, _ := crypt_tools.GenerateRSAKey()
	return privateKey
}

func (c *ClientConnection) getEdgeConnection() *EdgeConnection {
	return c.edgeConnections["localhost:8484"]
}

func (c *ClientConnection) Call(function string, data []byte) (result []byte, err error) {
	if len(function) > 255 {
		err = errors.New("wrong function len")
		return
	}
	ec := c.getEdgeConnection()
	if ec == nil {
		err = errors.New("no connection")
		return
	}

	frame := make([]byte, 1+len(function)+len(data))
	frame[0] = byte(len(function))
	copy(frame[1:], function)
	copy(frame[1+len(function):], data)

	result, err = ec.Call(c.address, frame)
	if err != nil {
		return
	}

	if len(result) < 1 {
		err = errors.New("wrong response (<1)")
		return
	}

	if result[0] == 0 {
		result = result[1:]
		err = nil
		return
	}

	if result[0] == 1 {
		result = nil
		err = errors.New(string(result[1:]))
		return
	}

	err = errors.New("wrong response (status byte)")
	return
}
