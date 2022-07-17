package http_server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ipoluianov/gomisc/http_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/config"
	"github.com/ipoluianov/xchg/core"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
)

type HttpServer struct {
	mtx          sync.Mutex
	started      bool
	core         *core.Core
	srv          *http.Server
	limiterStore limiter.Store
	config       config.Config
}

func NewHttpServer(conf config.Config, core *core.Core) *HttpServer {
	var err error
	var c HttpServer

	c.core = core
	c.config = conf

	// Setup limiter
	c.limiterStore, err = memorystore.New(&memorystore.Config{
		Tokens:   c.config.Http.MaxRequestsPerIPInSecond,
		Interval: 1 * time.Second,
	})
	if err != nil {
		logger.Error(err)
	}

	return &c
}

func (c *HttpServer) Start() {
	c.mtx.Lock()
	c.srv = &http.Server{
		Addr: ":" + fmt.Sprint(c.config.Http.HttpPort),
	}
	c.srv.Handler = c
	c.core.Start()
	go func() {
		err := c.srv.ListenAndServe()
		if err != nil {
			logger.Println("[HttpServer]", "[error]", "HttpServer thListen error: ", err)
		}
	}()
	c.mtx.Unlock()
}

func (c *HttpServer) Stop() error {
	ctx := context.Background()
	_ = c.limiterStore.Close(ctx)
	c.core.Stop()
	return c.srv.Close()
}

func (c *HttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var result []byte

	// Limiter
	////////////////////////////////////////////////////////////
	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	if !limiterOK {
		errString := []byte("too frequent request")
		result = make([]byte, 1+len(errString))
		result[0] = 1 // Error
		copy(result, errString)
		return
	}
	////////////////////////////////////////////////////////////
	// http://xchgx.example/?d=base64-encoded-request
	data64 := r.FormValue("d")
	f := r.FormValue("f")
	if len(f) == 0 {
		data, err := base64.StdEncoding.DecodeString(data64)
		if err != nil {
			errString := []byte(err.Error())
			result = make([]byte, 1+len(errString))
			result[0] = 1 // Error
			copy(result[1:], errString)
		} else {
			var processResult []byte
			processResult, err = c.core.ProcessFrame(ctx, data)
			if err != nil {
				errString := []byte(err.Error())
				result = make([]byte, 1+len(errString))
				result[0] = 1 // Error
				copy(result[1:], errString)
			} else {
				result = make([]byte, 1+len(processResult))
				result[0] = 0 // Success
				copy(result[1:], processResult)
			}
		}
		response64 := base64.StdEncoding.EncodeToString(result)
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(response64))
	} else {
		c.processServiceFunction(f, w)
	}
}

func (c *HttpServer) processServiceFunction(f string, w http.ResponseWriter) {
	var result []byte
	var err error
	switch f {
	case "i":
		result, err = c.core.Info()
	default:
		result = make([]byte, 0)
		err = errors.New("unknown function")
	}

	if err == nil {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(result))
	} else {
		w.WriteHeader(502)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(err.Error()))
	}
}
