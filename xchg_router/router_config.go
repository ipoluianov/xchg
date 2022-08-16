package xchg_router

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/ipoluianov/xchg/xchg"
)

type RouterConfig struct {
	HttpServerPort int `json:"http_server_port"`
	BinServerPort  int `json:"bin_server_port"`
}

func (c *RouterConfig) Init() {
	c.HttpServerPort = 8485
	c.BinServerPort = 8484
}

func LoadConfigFromFile(filePath string) (conf RouterConfig, err error) {
	conf.Init()

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
			err = errors.New(xchg.ERR_XCHG_ROUTER_CONFIG_IS_DIRECTORY)
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

	return
}
