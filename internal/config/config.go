package config

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

type Http struct {
	HttpPort                 int    `json:"http_port"`
	UsingProxy               bool   `json:"using_proxy"`
	MaxRequestsPerIPInSecond uint64 `json:"max_requests_per_ip_in_second"`
}

type Core struct {
	PurgeIntervalMs int `json:"purge_interval_ms"`
}

type Config struct {
	Core Core `json:"core"`
	Http Http `json:"http"`
}

func LoadFromFile(filePath string) (conf Config, err error) {
	conf.Http.HttpPort = 8987
	conf.Http.UsingProxy = false
	conf.Http.MaxRequestsPerIPInSecond = 10
	conf.Core.PurgeIntervalMs = 5000

	var fi os.FileInfo
	var bs []byte
	fi, err = os.Stat(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}

		// write config to file for user convenience if the file is not exist
		bs, err = json.MarshalIndent(conf, "", " ")
		_ = ioutil.WriteFile(filePath, bs, 0660) // it is just helper. ignore errors

	} else {
		if fi.IsDir() {
			err = errors.New("config.json is directory")
			return
		}
		bs, err = ioutil.ReadFile(filePath)
		if err != nil {
			return
		}
		err = json.Unmarshal(bs, &conf)
		if err != nil {
			return
		}
	}

	if conf.Core.PurgeIntervalMs < 0 || conf.Core.PurgeIntervalMs > 3600000 {
		err = errors.New("wrong conf.Core.PurgeIntervalMs")
	}

	if conf.Http.HttpPort < 1 || conf.Http.HttpPort > 65535 {
		err = errors.New("wrong conf.Http.HttpPort")
	}

	if conf.Http.MaxRequestsPerIPInSecond < 1 || conf.Http.MaxRequestsPerIPInSecond > 1000000 {
		err = errors.New("wrong conf.Http.MaxRequestsPerIPInSecond")
	}

	return
}
