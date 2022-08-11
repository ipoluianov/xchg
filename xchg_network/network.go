package xchg_network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Network struct {
	Ranges map[string]*Range
}

func NewNetwork() *Network {
	var c Network
	c.init()
	return &c
}

func NewNetworkFromBytes(rawContent []byte) (*Network, error) {
	var c Network
	c.init()
	json.Unmarshal(rawContent, &c)
	return &c, nil
}

func (c *Network) init() {
	c.Ranges = make(map[string]*Range)
}

func (c *Network) SetRange(prefix string, hosts []string) {
	r := NewRange(prefix)
	for _, h := range hosts {
		r.Hosts = append(r.Hosts, NewHost(h))
	}
	c.Ranges[prefix] = r
}

func (c *Network) String() string {
	return string(c.ToBytes())
}

func (c *Network) ToBytes() []byte {
	bs, _ := json.MarshalIndent(c, "", " ")
	return bs
}

func (c *Network) GetAddressesByPublicKey(publicKeyBS []byte) []string {
	SHAPublicKeyBS := sha256.Sum256(publicKeyBS)
	SHAPublicKeyHex := hex.EncodeToString(SHAPublicKeyBS[:])

	var preferredRange *Range
	preferredRangeScore := 0

	for _, r := range c.Ranges {
		rangeScore := 0
		for i := 0; i < len(SHAPublicKeyHex) && i < len(r.Prefix); i++ {
			if r.Prefix[i] == SHAPublicKeyHex[i] {
				rangeScore++
			}
		}
		if rangeScore == len(r.Prefix) && rangeScore > preferredRangeScore {
			preferredRange = r
			preferredRangeScore = rangeScore
		}
	}

	addresses := make([]string, 0)

	if preferredRange != nil {
		for _, host := range preferredRange.Hosts {
			addresses = append(addresses, host.Address)
		}
	}

	if defaultRange, ok := c.Ranges[""]; ok {
		for _, host := range defaultRange.Hosts {
			addresses = append(addresses, host.Address)
		}
	}

	return addresses
}
