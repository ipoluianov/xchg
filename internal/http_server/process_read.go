package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/internal/listener"
	"net/http"
	"time"
)

func (c *HttpServer) processR(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error
	var message *listener.Message

	logger.Println("read begin")

	ipAddr := c.getRealAddr(r)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {

		address := r.FormValue("a")

		// find listener
		listenerFound := false
		var l *listener.Listener
		c.mtx.Lock()
		l, listenerFound = c.listeners[address]
		if !listenerFound {
			l = listener.NewListener(address)
			c.listeners[address] = l
		}
		c.mtx.Unlock()

		var valid bool

		waitingDurationInMilliseconds := 10000
		waitingTick := 100
		waitingIterationCount := waitingDurationInMilliseconds / waitingTick

		for i := 0; i < waitingIterationCount; i++ {
			message, valid = l.Pull()
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
