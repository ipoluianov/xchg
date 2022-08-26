package xchg_network

type host struct {
	Address    string `json:"address"`
	Name       string `json:"name"`
	EthAddress string `json:"eth_addr"`
	SolAddress string `json:"sol_addr"`
}

func NewHost(address string) *host {
	var c host
	c.Address = address
	c.Name = "MainNet"
	c.EthAddress = "0x60087f17b9dAF691DEd6c40Cb1fA6CE4407fa58C"
	c.SolAddress = "todo"
	return &c
}
