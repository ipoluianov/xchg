package http_server

import (
	"context"
	"errors"
	"github.com/gorilla/mux"
	listener2 "github.com/ipoluyanov/xchg/internal/listener"
	"github.com/ipoluyanov/xchg/internal/logger"
	"net/http"
	"time"
)

func (c *HttpServer) processR(w http.ResponseWriter, r *http.Request) {
	var err error
	var message *listener2.Message

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
		var listener *listener2.Listener
		c.mtx.Lock()
		listener, listenerFound = c.listeners[id]
		if !listenerFound {
			listener = listener2.NewListener(id)
			c.listeners[id] = listener
		}
		c.mtx.Unlock()

		var valid bool

		waitingDurationInMilliseconds := 60000
		waitingTick := 100
		waitingIterationCount := waitingDurationInMilliseconds / waitingTick

		for i := 0; i < waitingIterationCount; i++ {
			message, valid = listener.Pull()
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
