package http_server

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/core"
	"net/http"
)

func (c *HttpServer) processI(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error
	var info core.Info

	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		info, err = c.core.Info(r.Context())
	}

	var bs []byte
	bs, err = json.MarshalIndent(info, "", " ")
	if err == nil {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(bs)
	} else {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	}

	logger.Println("processR from [", ipAddr, "]")
}
