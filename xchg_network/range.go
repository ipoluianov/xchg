package xchg_network

import "strings"

type rng struct {
	Prefix string  `json:"prefix"`
	Hosts  []*host `json:"hosts"`
}

func NewRange(prefix string) *rng {
	var c rng
	c.Prefix = strings.ToLower(prefix)
	c.Hosts = make([]*host, 0)
	return &c
}

func (c *rng) addHostIfNotExists(address string) {
	for _, h := range c.Hosts {
		if h.Address == address {
			return
		}
	}
	c.Hosts = append(c.Hosts, NewHost(address))
}
