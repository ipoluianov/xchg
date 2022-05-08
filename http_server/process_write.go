package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	listener2 "github.com/ipoluianov/xchg/core"
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

		// find core
		listenerFound := false
		var listener *listener2.Listener
		c.mtx.Lock()
		listener, listenerFound = c.listeners[address]
		c.mtx.Unlock()

		// push message
		if listenerFound && listener != nil {
			err = listener.PushMessage([]byte(data))
		} else {
			err = errors.New("no route to host")
		}
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
