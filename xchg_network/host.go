package xchg_network

type host struct {
	Address   string  `json:"address"`
	Name      string  `json:"name"`
	PublicKey string  `json:"pk"`
	Score     float64 `json:"sc"`

	online bool
}

func NewHost(address string) *host {
	var c host
	c.Address = address
	return &c
}

func (c *host) SetOnline(online bool) {
	c.online = false
}

func (c *host) recalcScore() {
	if !c.online {
		c.Score = 0
	}
}
