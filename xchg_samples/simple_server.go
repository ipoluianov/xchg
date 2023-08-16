package xchg_samples

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/rand"
	"time"

	"github.com/ipoluianov/xchg/xchg"
)

type SimpleServer struct {
	serverConnection *xchg.Peer
	defaultResponse  []byte
}

func NewSimpleServer(privateKey *rsa.PrivateKey) *SimpleServer {
	var c SimpleServer
	c.serverConnection = xchg.NewPeer(privateKey)
	c.serverConnection.SetProcessor(&c)

	c.defaultResponse = make([]byte, 10)
	rand.Read(c.defaultResponse)
	return &c
}

func (c *SimpleServer) Start() {
	c.serverConnection.Start(true)
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

func (c *SimpleServer) ServerProcessorCall(authData []byte, function string, parameter []byte) (response []byte, err error) {
	switch function {
	case "version":
		//response = []byte("simple server 2.42 0123456789|0123456789|0123456789|0123456789")
		//response = make([]byte, 3000)
		//rand.Read(response)
		response = c.defaultResponse
	case "time":
		strTime := time.Now().String()
		response = []byte(strTime)
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
		err = errors.New(xchg.ERR_XCHG_NOT_IMPLEMENTED)
	}

	return
}
