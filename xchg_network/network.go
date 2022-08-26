package xchg_network

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"sort"
	"strings"
	"sync"
)

type Network struct {
	mtx sync.Mutex

	Ranges   []*rng  `json:"ranges"`
	Gateways []*host `json:"gateways"`
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

func NewNetworkFromFileOrCreate(fileName string) (network *Network) {
	var bs []byte
	var err error

	bs, err = ioutil.ReadFile(fileName)
	if err != nil {
		network = NewNetworkDefault()
		network.SaveToFile(fileName)
	} else {
		network, err = NewNetworkFromBytes(bs)
		if err != nil {
			network = NewNetworkDefault()
		}
	}
	return
}

func NewNetworkDefault() *Network {
	network := NewNetwork()
	s1 := "54.37.73.160:8484"
	s2 := "54.37.73.229:8484"

	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, s1)
		network.AddHostToRange(rangePrefix, s2)
	}
	return network
}

func (c *Network) SaveToFile(fileName string) error {
	bs := c.toBytes()
	err := ioutil.WriteFile(fileName, bs, 0660)
	return err
}

func (c *Network) init() {
	c.Ranges = make([]*rng, 0)
	c.Gateways = make([]*host, 0)
}

func (c *Network) AddHostToRange(prefix string, address string) {
	prefix = strings.ToLower(prefix)

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

func (c *Network) GetNodesAddressesByAddress(address string) []string {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	addressBS, err := base32.StdEncoding.DecodeString(strings.ToUpper(address))
	if err != nil {
		return make([]string, 0)
	}

	SHAPublicKeyHex := hex.EncodeToString(addressBS)
	SHAPublicKeyHex = strings.ToLower(SHAPublicKeyHex)

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

	// Randomize
	rnd := make([]byte, len(addresses))
	rand.Read(rnd)
	sort.Slice(addresses, func(i, j int) bool {
		return rnd[i] < rnd[j]
	})

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
