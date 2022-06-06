package http_server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
)

func (c *HttpServer) writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(404)
	_, _ = w.Write([]byte(err.Error()))
}

const (
	FunctionCodeInitServer1 = byte(0x00)
	FunctionCodeInitServer2 = byte(0x01)
	FunctionCodeGetRequest  = byte(0x02)
	FunctionCodePutResponse = byte(0x03)
	FunctionCodeCall        = byte(0x04)
	FunctionCodePing        = byte(0x05)
)

func (c *HttpServer) processB(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Getting data
	data64 := r.FormValue("d")
	data, err := base64.StdEncoding.DecodeString(data64)
	if err != nil {
		c.writeError(w, err)
		return
	}

	// Getting function code
	dataLen := len(data)
	if dataLen < 1 {
		c.writeError(w, errors.New("wrong data length (<1)"))
		return
	}
	functionCode := data[0]
	data = data[1:]

	// Executing function
	var result []byte
	switch functionCode {
	case FunctionCodeInitServer1:
		result, err = c.core.InitServer1(ctx, data)
	case FunctionCodeInitServer2:
		result, err = c.core.InitServer2(ctx, data)
	case FunctionCodeGetRequest:
		result, err = c.core.GetNextRequest(ctx, data)
	case FunctionCodePutResponse:
		err = c.core.PutResponse(ctx, data)
	case FunctionCodeCall:
		result, err = c.core.Call(ctx, data)
	case FunctionCodePing:
		result, err = c.core.Ping(ctx, data)
	}

	// Sending result
	if err != nil {
		c.writeError(w, err)
		return
	}
	response64 := base64.StdEncoding.EncodeToString(result)
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(response64))
}
