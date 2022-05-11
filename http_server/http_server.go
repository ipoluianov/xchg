package http_server

import (
	"context"
	"fmt"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/config"
	"github.com/ipoluianov/xchg/core"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
	"log"
	"net/http"
	"time"
)

type HttpServer struct {
	core         *core.Core
	srv          *http.Server
	limiterStore limiter.Store
	config       config.Config
}

func NewHttpServer(conf config.Config) *HttpServer {
	var err error
	var c HttpServer

	c.core = core.NewCore(conf)
	c.config = conf

	// Setup limiter
	c.limiterStore, err = memorystore.New(&memorystore.Config{
		Tokens:   c.config.Http.MaxRequestsPerIPInSecond,
		Interval: 1 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	return &c
}

func (c *HttpServer) Start() {
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
}

func (c *HttpServer) Stop() error {
	ctx := context.Background()
	_ = c.limiterStore.Close(ctx)
	c.core.Stop()
	return c.srv.Close()
}

func (c *HttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	function := r.FormValue("f")
	ctx := context.Background()
	switch function {
	case "w":
		c.processW(ctx, w, r)
	case "r":
		c.processR(ctx, w, r)
	case "x":
		c.processX(ctx, w, r)
	case "i":
		c.processI(ctx, w, r)
	case "p":
		c.processP(ctx, w, r)
	default:
		{
			w.WriteHeader(400)
			_, _ = w.Write([]byte("need 'f'"))
		}
	}
}
