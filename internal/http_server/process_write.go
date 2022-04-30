package http_server

import (
	"context"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	listener2 "github.com/ipoluyanov/xchg/internal/listener"
	"net/http"
)

func (c *HttpServer) processW(w http.ResponseWriter, r *http.Request) {
	var err error

	ctx := context.Background()

	// get properties
	ipAddr := c.getRealAddr(r)

	tokens, rem, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	fmt.Println("limiter tokens", tokens, "remain", rem)
	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {

		data := r.FormValue("d")
		id := mux.Vars(r)["id"]

		// find listener
		listenerFound := false
		var listener *listener2.Listener
		c.mtx.Lock()
		listener, listenerFound = c.listeners[id]
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
