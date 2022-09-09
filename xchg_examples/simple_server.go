package xchg_examples

import (
	"crypto/rsa"
	"encoding/json"
	"errors"

	"github.com/ipoluianov/xchg/connection"
	"github.com/ipoluianov/xchg/xchg"
)

type SimpleServer struct {
	serverConnection *connection.Peer
}

func NewSimpleServer(privateKey *rsa.PrivateKey) *SimpleServer {
	var c SimpleServer
	c.serverConnection = connection.NewPeer(privateKey)
	c.serverConnection.SetProcessor(&c)
	return &c
}

func (c *SimpleServer) Start() {
	c.serverConnection.Start()
}

func (c *SimpleServer) Stop() {
	c.serverConnection.Stop()
}

func (c *SimpleServer) ServerProcessorAuth(authData []byte) (err error) {
	if string(authData) == "pass" {
		return nil
	}
	return errors.New(xchg.ERR_XCHG_ACCESS_DENIED)
}

func (c *SimpleServer) ServerProcessorCall(function string, parameter []byte) (response []byte, err error) {
	switch function {
	case "version":
		response = []byte("simple server 2.42 0123456789|0123456789|0123456789|0123456789")
		//response = make([]byte, 122400)
	case "json-api":
		type InputStruct struct {
			A int
			B int
		}
		var request InputStruct
		err = json.Unmarshal(parameter, &request)
		if err != nil {
			return
		}
		type OutputStruct struct {
			C int
		}
		var resp OutputStruct
		resp.C = request.A + request.B
		response, err = json.MarshalIndent(resp, "", " ")
	default:
		err = errors.New(xchg.ERR_SIMPLE_SERVER_FUNC_IS_NOT_IMPL)
	}

	return
}
