package xchg

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ipoluianov/gomisc/logger"
)

type HttpServer struct {
	srv    *http.Server
	config Config
	router *Router
}

type HttpServerConfig struct {
	Port int `json:"port"`
}

func (c *HttpServerConfig) Init() {
	c.Port = 8485
}

func (c *HttpServerConfig) Check() (err error) {
	if c.Port < 1 || c.Port > 65535 {
		err = errors.New("wrong HttpConfig.Port")
	}
	return
}

func (c *HttpServerConfig) Log() {
	logger.Println("http config")
	logger.Println("http config", "Port =", c.Port)
}

func NewHttpServer(conf Config, router *Router) *HttpServer {
	var c HttpServer
	c.config = conf
	c.router = router
	return &c
}

func (c *HttpServer) Start() {
	logger.Println("HttpServer starting")
	c.srv = &http.Server{
		Addr: ":" + fmt.Sprint(c.config.HttpServer.Port),
	}
	c.srv.Handler = c
	go func() {
		err := c.srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.Println("[HttpServer]", "[error]", "HttpServer thListen error: ", err)
		}
	}()
	logger.Println("HttpServer started")
}

func (c *HttpServer) Stop() error {
	return c.srv.Close()
}

func (c *HttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//ctx := context.Background()
	var result []byte

	switch r.URL.Path {
	case "/":
		result = []byte("index")
	case "/debug":
		result = []byte(c.router.DebugInfo())
	}

	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(result)
}
