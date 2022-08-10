package xchg

import (
	"fmt"
	"net/http"

	"github.com/ipoluianov/gomisc/logger"
)

type HttpServer struct {
	srv    *http.Server
	port   int
	router *Router
}

func NewHttpServer(port int, router *Router) *HttpServer {
	var c HttpServer
	c.port = port
	c.router = router
	return &c
}

func (c *HttpServer) Start() {
	logger.Println("HttpServer starting")
	c.srv = &http.Server{
		Addr: ":" + fmt.Sprint(c.port),
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
