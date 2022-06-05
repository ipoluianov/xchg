package http_server

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"net/http"
)

func (c *HttpServer) processPut(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	var response []byte

	// get properties
	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	//logger.Println("write addr:", ipAddr)

	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		data64 := r.FormValue("d")
		var data []byte
		data, err = base64.StdEncoding.DecodeString(data64)
		if err != nil {
			return
		}
		c.core.PutResponse(ctx, data)
	}

	// Write result
	if err != nil {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	} else {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(response)
	}
	return
}
