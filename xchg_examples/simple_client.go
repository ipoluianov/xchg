package xchg_examples

import (
	"encoding/base32"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/xchg/xchg_connections"
	"github.com/ipoluianov/xchg/xchg_network"
)

type SimpleClient struct {
	client *xchg_connections.ClientConnection
}

func NewSimpleClient(address string, network *xchg_network.Network) *SimpleClient {
	var c SimpleClient
	privateKey, _ := crypt_tools.GenerateRSAKey()
	privateKey32 := base32.StdEncoding.EncodeToString(crypt_tools.RSAPrivateKeyToDer(privateKey))
	c.client = xchg_connections.NewClientConnection(network, address, privateKey32, "pass", nil)
	return &c
}

func (c *SimpleClient) Version() (result string, err error) {
	var resultBS []byte
	resultBS, err = c.client.Call("version", nil)
	result = string(resultBS)
	return
}

func (c *SimpleClient) Calculate(a int, b int) (result int, err error) {
	c.client.Call("static-string", nil)
	return
}
