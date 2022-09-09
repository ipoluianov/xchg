package xchg_examples

import (
	"time"

	"github.com/ipoluianov/xchg/connection"
)

type SimpleClient struct {
	address string
	client  *connection.Peer
}

func NewSimpleClient(address string) *SimpleClient {
	var c SimpleClient
	c.address = address
	c.client = connection.NewPeer(nil)
	return &c
}

func (c *SimpleClient) Version() (result string, err error) {
	var resultBS []byte
	resultBS, err = c.client.Call(c.address, "pass", "version", nil, time.Second)
	result = string(resultBS)
	return
}

func (c *SimpleClient) Calculate(a int, b int) (result int, err error) {
	c.client.Call(c.address, "pass", "static-string", nil, time.Second)
	return
}
