package http_server

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/ipoluianov/xchg/internal/listener"
	"github.com/ipoluianov/xchg/internal/logger"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
	"log"
	"net/http"
	"sync"
	"time"
)

type HttpServer struct {
	srv                *http.Server
	r                  *mux.Router
	mtx                sync.Mutex
	listeners          map[string]*listener.Listener
	limiterStore       limiter.Store
	config             Config
	stopPurgeRoutineCh chan struct{}
}

func NewHttpServer(config Config) *HttpServer {
	var err error
	var c HttpServer

	// Configuration
	usingProxy := config.UsingProxy
	purgeInterval := 5 * time.Second
	if config.PurgeInterval > 0 {
		purgeInterval = config.PurgeInterval
	}
	maxRequestsPerIPInSecond := uint64(10)
	if config.MaxRequestsPerIPInSecond > 0 {
		maxRequestsPerIPInSecond = config.MaxRequestsPerIPInSecond
	}
	c.config = Config{
		UsingProxy:               usingProxy,
		PurgeInterval:            purgeInterval,
		MaxRequestsPerIPInSecond: maxRequestsPerIPInSecond,
	}

	// Setup limiter
	c.listeners = make(map[string]*listener.Listener)
	c.limiterStore, err = memorystore.New(&memorystore.Config{
		Tokens:   c.config.MaxRequestsPerIPInSecond,
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
	c.r = mux.NewRouter()
	c.r.HandleFunc("/r/{id}", c.processR)
	c.r.HandleFunc("/w/{id}", c.processW)
	c.r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	})
	c.srv = &http.Server{
		Addr: ":8987",
	}
	c.srv.Handler = c.r
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
