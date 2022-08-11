package xchg_network

type Host struct {
	Address string
}

func NewHost(address string) *Host {
	var c Host
	c.Address = address
	return &c
}
