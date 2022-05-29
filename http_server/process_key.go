package http_server

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"net/http"
)

func (c *HttpServer) processK(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var encryptedSymKey string
	var err error

	// get properties
	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	logger.Println("init from IP:", ipAddr)

	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	if !limiterOK {
		err = errors.New("too frequent requests")
	} else {
		publicKey64 := r.FormValue("public_key")
		address := r.FormValue("a")
		logger.Println("init from a:", address, "public_key", publicKey64)
		encryptedSymKey, err = c.core.GenerateAndEncryptSymmetricKeyForNode(address, publicKey64)
	}

	// Write result
	if err != nil {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(err.Error()))
	} else {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encryptedSymKey))
	}
}
