package xchg_samples

import (
	"time"

	"github.com/ipoluianov/xchg/xchg"
)

type SimpleClient struct {
	address string
	client  *xchg.Peer
}

func NewSimpleClient(address string) *SimpleClient {
	var c SimpleClient
	c.address = address
	c.client = xchg.NewPeer(nil)
	c.client.StartHttpOnly()
	return &c
}

func (c *SimpleClient) Version() (result string, err error) {
	var resultBS []byte
	resultBS, err = c.client.Call(c.address, "pass", "version", nil, 2*time.Second)
	result = string(resultBS)
	return
}

func (c *SimpleClient) Calculate(a int, b int) (result int, err error) {
	c.client.Call(c.address, "pass", "static-string", nil, time.Second)
	return
}
