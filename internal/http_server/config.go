package http_server

import "time"

type Config struct {
	UsingProxy               bool
	PurgeInterval            time.Duration
	MaxRequestsPerIPInSecond uint64
}
