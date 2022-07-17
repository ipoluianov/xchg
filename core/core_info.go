package core

import (
	"encoding/json"
)

type InfoStat struct {
	Received int64 `json:"received"`
}

func (c *Core) Info() (result []byte, err error) {
	c.mtx.Lock()
	c.statistics.Info.Received++
	statistics := c.statistics
	c.mtx.Unlock()
	result, err = json.MarshalIndent(statistics, "", " ")
	return
}
