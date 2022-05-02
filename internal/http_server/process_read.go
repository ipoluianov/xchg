package http_server

import (
	"context"
	"errors"
	"github.com/gorilla/mux"
	"github.com/ipoluianov/xchg/internal/listener"
	"github.com/ipoluianov/xchg/internal/logger"
	"net/http"
	"time"
)

func (c *HttpServer) processR(w http.ResponseWriter, r *http.Request) {
	var err error
	var message *listener.Message

	logger.Println("read begin")

	ctx := context.Background()
	ipAddr := c.getRealAddr(r)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {

		id := mux.Vars(r)["id"]

		// find listener
		listenerFound := false
		var l *listener.Listener
		c.mtx.Lock()
		l, listenerFound = c.listeners[id]
		if !listenerFound {
			l = listener.NewListener(id)
			c.listeners[id] = l
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

	logger.Println("processR from [", ipAddr, "]")
}
