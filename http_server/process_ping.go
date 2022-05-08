package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"net/http"
)

func (c *HttpServer) processP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error

	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	listenerInfo := ""

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		address := r.FormValue("a")
		listenerInfo, err = c.core.Ping(r.Context(), address)
	}

	if err == nil {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(listenerInfo))
	} else {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	}

	logger.Println("processR from [", ipAddr, "]")
}
