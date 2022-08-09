package xchg

import (
	"encoding/json"
	"errors"
	"time"
)

type SimpleServer struct {
}

func NewSimpleServer(serverPrivateKey string) *SimpleServer {
	var c SimpleServer
	s := NewServerConnection(serverPrivateKey)
	s.SetProcessor(&c)
	s.Start()
	s = nil
	return &c
}

func (c *SimpleServer) Start() {
	time.Sleep(1000 * time.Second)
}

func (c *SimpleServer) ServerProcessorAuth(authData []byte) (err error) {
	if string(authData) == "pass" {
		return nil
	}
	return errors.New("access denied")
}

func (c *SimpleServer) ServerProcessorCall(function string, parameter []byte) (response []byte, err error) {
	switch function {
	case "version":
		response = []byte("simple server 2.42")
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
		err = errors.New("function is not implemented")
	}

	return
}
