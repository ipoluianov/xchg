package http_server

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ipoluianov/gomisc/logger"
	"net/http"
	"time"
)

func (c *HttpServer) processI(w http.ResponseWriter, r *http.Request) {
	var err error
	type Info struct {
		DT            time.Time `json:"dt"`
		ListenerCount int       `json:"lc"`
	}
	var info Info

	ctx := context.Background()
	ipAddr := c.getRealAddr(r)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)

	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		c.mtx.Lock()
		info.DT = time.Now()
		info.ListenerCount = len(c.listeners)
		c.mtx.Unlock()
	}

	var bs []byte
	bs, err = json.MarshalIndent(info, "", " ")
	if err == nil {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(bs)
	} else {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	}

	logger.Println("processR from [", ipAddr, "]")
}
