package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/core"
	"net/http"
)

func (c *HttpServer) processR(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error
	var message *core.Message

	logger.Println("read begin")

	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		address := r.FormValue("a")
		message, err = c.core.Read(r.Context(), address)
	}

	if err == nil && message != nil {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(message.Data)
	} else {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("no data"))
	}

	logger.Println("processR end from [", ipAddr, "]")
}
