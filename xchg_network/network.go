package xchg_network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"sync"
)

type Network struct {
	mtx sync.Mutex

	Ranges []*rng `json:"ranges"`
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

func NewNetworkFromFile(fileName string) (*Network, error) {
	var bs []byte
	var err error

	bs, err = ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	network, err := NewNetworkFromBytes(bs)
	if err != nil {
		return nil, err
	}

	return network, nil
}

func (c *Network) SaveToFile(fileName string) error {
	bs := c.toBytes()
	err := ioutil.WriteFile(fileName, bs, 0660)
	return err
}

func (c *Network) init() {
	c.Ranges = make([]*rng, 0)
}

func (c *Network) AddHostToRange(prefix string, address string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	foundRange := false
	for _, r := range c.Ranges {
		if r.Prefix == prefix {
			r.addHostIfNotExists(address)
			foundRange = true
			break
		}
	}

	if !foundRange {
		r := NewRange(prefix)
		r.addHostIfNotExists(address)
		c.Ranges = append(c.Ranges, r)
	}
}

func (c *Network) String() string {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return string(c.toBytes())
}

func (c *Network) toBytes() []byte {
	bs, _ := json.MarshalIndent(c, "", " ")
	return bs
}

func (c *Network) GetAddressesByPublicKey(publicKeyBS []byte) []string {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	SHAPublicKeyBS := sha256.Sum256(publicKeyBS)
	SHAPublicKeyHex := hex.EncodeToString(SHAPublicKeyBS[:])

	var preferredRange *rng
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
	return addresses
}

func (c *Network) SetHostOnline(address string, online bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for _, r := range c.Ranges {
		for _, h := range r.Hosts {
			if h.Address == address {
				h.setOnline(online)
			}
		}
	}
}
