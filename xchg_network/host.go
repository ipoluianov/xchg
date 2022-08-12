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
	c.online = true
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
