package xchg_network

type Range struct {
	Prefix string
	Hosts  []*Host
}

func NewRange(prefix string) *Range {
	var c Range
	c.Prefix = prefix
	c.Hosts = make([]*Host, 0)
	return &c
}
