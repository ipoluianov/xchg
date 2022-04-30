package http_server

import (
	"net"
	"net/http"
	"strings"
)

func (c *HttpServer) getRealAddr(r *http.Request) string {
	remoteIP := ""
	if parts := strings.Split(r.RemoteAddr, ":"); len(parts) == 2 {
		remoteIP = parts[0]
	}
	if c.config.UsingProxy {
		if xff := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(xff) > 0 {
			addresses := strings.Split(xff, ",")
			lastFwd := addresses[len(addresses)-1]
			if ip := net.ParseIP(lastFwd); ip != nil {
				remoteIP = ip.String()
			}
		} else if xri := r.Header.Get("X-Real-Ip"); len(xri) > 0 {
			if ip := net.ParseIP(xri); ip != nil {
				remoteIP = ip.String()
			}
		}
	}
	return remoteIP
}
