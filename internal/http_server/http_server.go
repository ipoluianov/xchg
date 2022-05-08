package http_server

import (
	"context"
	"fmt"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/internal/config"
	"github.com/ipoluianov/xchg/internal/listener"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
	"log"
	"net/http"
	"sync"
	"time"
)

type HttpServer struct {
	srv                *http.Server
	mtx                sync.Mutex
	listeners          map[string]*listener.Listener
	limiterStore       limiter.Store
	config             config.Config
	stopPurgeRoutineCh chan struct{}
}

func NewHttpServer(conf config.Config) *HttpServer {
	var err error
	var c HttpServer

	c.config = conf

	// Setup limiter
	c.listeners = make(map[string]*listener.Listener)
	c.limiterStore, err = memorystore.New(&memorystore.Config{
		Tokens:   c.config.Http.MaxRequestsPerIPInSecond,
		Interval: 1 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	// sweeper
	c.stopPurgeRoutineCh = make(chan struct{})
	go c.purgeRoutine()

	return &c
}

func (c *HttpServer) Start() {
	c.srv = &http.Server{
		Addr: ":" + fmt.Sprint(c.config.Http.HttpPort),
	}
	c.srv.Handler = c
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
	close(c.stopPurgeRoutineCh)
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
