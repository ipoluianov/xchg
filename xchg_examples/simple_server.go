package xchg_examples

import (
	"encoding/json"
	"errors"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_connections"
	"github.com/ipoluianov/xchg/xchg_network"
)

type SimpleServer struct {
	serverPrivateKey32 string
	network            *xchg_network.Network
	serverConnection   *xchg_connections.ServerConnection
}

func NewSimpleServer(serverPrivateKey32 string, network *xchg_network.Network) *SimpleServer {
	var c SimpleServer
	c.serverPrivateKey32 = serverPrivateKey32
	c.network = network
	c.serverConnection = xchg_connections.NewServerConnection()
	c.serverConnection.SetProcessor(&c)
	return &c
}

func (c *SimpleServer) Start() {
	c.serverConnection.Start(c.serverPrivateKey32, c.network)
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
		//response = []byte("simple server 2.42")
		response = make([]byte, 122400)
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
