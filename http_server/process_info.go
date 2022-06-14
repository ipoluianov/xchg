package http_server

import (
	"context"
	"encoding/json"
	"github.com/ipoluianov/xchg/core"
	"net/http"
)

func (c *HttpServer) processI(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var err error
	var info core.Info

	info, err = c.core.Info(r.Context())

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
}
