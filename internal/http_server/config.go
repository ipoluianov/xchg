package http_server

import "time"

type ConfigHttp struct {
	HttpPort                 int    `json:"http_port"`
	UsingProxy               bool   `json:"using_proxy"`
	MaxRequestsPerIPInSecond uint64 `json:"max_requests_per_ip_in_second"`
}

type ConfigCore struct {
	PurgeInterval time.Duration `json:"purge_interval"`
}

type Config struct {
	Core ConfigCore `json:"core"`
	Http ConfigHttp `json:"http"`
}
