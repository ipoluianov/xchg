package xchg

import (
	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

type SimpleClient struct {
	client *ClientConnection
}

func NewSimpleClient(serverPublicKey58 string, network *Network) *SimpleClient {
	var c SimpleClient
	privateKey, _ := crypt_tools.GenerateRSAKey()
	privateKey58 := base58.Encode(crypt_tools.RSAPrivateKeyToDer(privateKey))
	c.client = NewClientConnection(network, serverPublicKey58, privateKey58, "pass")
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
