package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	core2 "github.com/ipoluianov/xchg/core"
	"net/http"
	"time"
)

func (c *HttpServer) processR(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error
	var message *core2.Message

	logger.Println("read begin")

	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {

		address := r.FormValue("a")

		// find core
		listenerFound := false
		var l *core2.Listener
		c.mtx.Lock()
		l, listenerFound = c.listeners[address]
		if !listenerFound {
			l = core2.NewListener(address)
			c.listeners[address] = l
		}
		c.mtx.Unlock()

		var valid bool

		waitingDurationInMilliseconds := 10000
		waitingTick := 100
		waitingIterationCount := waitingDurationInMilliseconds / waitingTick

		for i := 0; i < waitingIterationCount; i++ {
			message, valid = l.Pull()
			if r.Context().Err() != nil {
				break
			}

			if !valid {
				time.Sleep(time.Duration(waitingTick) * time.Millisecond)
				continue
			}
			break
		}

		if !valid {
			err = errors.New("no data")
		}
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
