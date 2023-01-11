package xchg_samples

import (
	"crypto/rsa"
	"errors"

	"github.com/ipoluianov/xchg/xchg"
)

type Server struct {
	serverConnection *xchg.Peer
	privateKey       *rsa.PrivateKey
	accessKey        string
	processor        func(function string, parameter []byte) (response []byte, err error)
}

func StartServer(privateKey *rsa.PrivateKey, accessKey string, processor func(function string, parameter []byte) (response []byte, err error)) *Server {
	var c Server
	c.privateKey = privateKey
	c.serverConnection = xchg.NewPeer(privateKey)
	c.serverConnection.SetProcessor(&c)
	c.processor = processor
	c.serverConnection.StartHttpOnly()
	return &c
}

func StartServerFast(accessKey string, processor func(function string, parameter []byte) (response []byte, err error)) *Server {
	privateKey, _ := xchg.GenerateRSAKey()
	s := StartServer(privateKey, accessKey, processor)
	s.privateKey = privateKey
	return s
}

func (c *Server) Address() string {
	return xchg.AddressForPublicKey(&c.privateKey.PublicKey)
}

func (c *Server) Stop() {
	c.serverConnection.Stop()
}

func (c *Server) ServerProcessorAuth(authData []byte) (err error) {
	if string(authData) == c.accessKey {
		return nil
	}
	return errors.New(xchg.ERR_XCHG_ACCESS_DENIED)
}

func (c *Server) ServerProcessorCall(function string, parameter []byte) (response []byte, err error) {
	if c.processor != nil {
		return c.processor(function, parameter)
	}
	return nil, errors.New("not implemented")
}
