package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"net/http"
)

func (c *HttpServer) processW(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error

	// get properties
	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	logger.Println("write addr:", ipAddr)

	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	//fmt.Println("limiter tokens", tokens, "remain", rem)
	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		data := r.FormValue("d")
		address := r.FormValue("a")
		err = c.core.Write(r.Context(), address, []byte(data))
	}

	// Write result
	if err != nil {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	} else {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	//logger.Println("processW from [", ipAddr, "]", "data", data, "id", id, "err", err)
}
