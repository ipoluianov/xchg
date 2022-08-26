package xchg_network

type host struct {
	Address    string  `json:"address"`
	Name       string  `json:"name"`
	PublicKey  string  `json:"pk"`
	Score      float64 `json:"sc"`
	EthAddress string  `json:"eth_addr"`
	SolAddress string  `json:"sol_addr"`

	online bool
}

func NewHost(address string) *host {
	var c host
	c.Address = address
	c.online = true
	c.EthAddress = "0x60087f17b9dAF691DEd6c40Cb1fA6CE4407fa58C"
	c.SolAddress = "todo"
	c.recalcScore()
	return &c
}

func (c *host) setOnline(online bool) {
	c.online = false
}

func (c *host) recalcScore() {
	if !c.online {
		c.Score = 0
	} else {
		c.Score = 1
	}
}
