package xchg

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
)

type Config struct {
	RouterServer     RouterServerConfig `json:"router_server"`
	RouterConnection ConnectionConfig   `json:"connection"`
}

func (c *Config) Init() {
	c.RouterServer.Init()
	c.RouterConnection.Init()
}

func (c *Config) Check() (err error) {
	err = c.RouterServer.Check()
	if err != nil {
		return
	}
	err = c.RouterConnection.Check()
	return
}

func LoadConfigFromFile(filePath string) (conf Config, err error) {
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

	err = conf.Check()
	return
}
