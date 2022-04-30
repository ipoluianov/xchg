package http_server

import "time"

type Config struct {
	UsingProxy               bool          `json:"using_proxy"`
	PurgeInterval            time.Duration `json:"purge_interval"`
	MaxRequestsPerIPInSecond uint64        `json:"max_requests_per_ip_in_second"`
}
