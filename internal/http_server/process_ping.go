package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/internal/listener"
	"net/http"
)

func (c *HttpServer) processP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error

	ipAddr := c.getRealAddr(r)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	listenerInfo := ""

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		address := r.FormValue("a")

		var l *listener.Listener
		listenerFound := false
		c.mtx.Lock()
		l, listenerFound = c.listeners[address]
		if !listenerFound {
			err = errors.New("no route to host")
		} else {
			listenerInfo = l.LastGetDT().String()
		}
		c.mtx.Unlock()
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
