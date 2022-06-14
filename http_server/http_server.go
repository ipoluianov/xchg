package http_server

import (
	"context"
	"fmt"
	"github.com/ipoluianov/gomisc/http_tools"
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
	ctx := context.Background()

	// Limiter
	////////////////////////////////////////////////////////////
	ipAddr := http_tools.GetRealAddr(r, c.config.Http.UsingProxy)
	_, _, _, limiterOK, _ := c.limiterStore.Take(ctx, ipAddr)
	if !limiterOK {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("too frequent request"))
		return
	}
	////////////////////////////////////////////////////////////

	function := r.FormValue("f")
	switch function {
	// client
	case "b":
		c.processB(ctx, w, r)
	case "i":
		c.processI(ctx, w, r)
	default:
		{
			w.WriteHeader(400)
			_, _ = w.Write([]byte("need 'f'"))
		}
	}
}
