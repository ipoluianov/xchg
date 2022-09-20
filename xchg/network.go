package xchg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Network struct {
	mtx sync.Mutex

	fromInternet       bool
	fromInternetLoaded bool

	Name       string  `json:"name"`
	EthAddress string  `json:"eth_addr"`
	SolAddress string  `json:"sol_addr"`
	Ranges     []*rng  `json:"ranges"`
	Gateways   []*host `json:"gateways"`
}

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

func NewNetwork() *Network {
	var c Network
	c.init()
	return &c
}

func NewNetworkFromInternet() *Network {
	var c Network
	c.init()
	c.fromInternet = true
	c.fromInternetLoaded = false
	go c.loadNetworkFromInternet()
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
	s3 := "134.0.115.16:8484"

	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, s1)
		network.AddHostToRange(rangePrefix, s2)
		network.AddHostToRange(rangePrefix, s3)
	}
	return network
}

func NewNetworkLocalhost() *Network {
	network := NewNetwork()
	s1 := "127.0.0.1:8484"

	for r := 0; r < 16; r++ {
		rangePrefix := fmt.Sprintf("%X", r)
		network.AddHostToRange(rangePrefix, s1)
	}
	return network
}

func (c *Network) ReloadFromInternet() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.fromInternet = true
	c.fromInternetLoaded = false
}

func (c *Network) loadNetworkFromInternet() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if !c.fromInternet {
		return
	}

	if c.fromInternetLoaded {
		return
	}

	resp, err := http.Get("https://xchgx.net/network.json")
	if err != nil {
		return
	}
	var networkBS []byte
	networkBS, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}
	err = json.Unmarshal(networkBS, c)
	if err == nil {
		c.fromInternetLoaded = true
	}
}

func (c *Network) SaveToFile(fileName string) error {
	bs := c.toBytes()
	err := ioutil.WriteFile(fileName, bs, 0666)
	return err
}

func (c *Network) init() {
	c.Ranges = make([]*rng, 0)
	c.Gateways = make([]*host, 0)
	c.Name = "MainNet"
	c.EthAddress = "0x60087f17b9dAF691DEd6c40Cb1fA6CE4407fa58C"
	c.SolAddress = "todo"
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
	c.loadNetworkFromInternet()

	c.mtx.Lock()
	defer c.mtx.Unlock()

	address = strings.ToLower(address)
	shaAddress := sha256.Sum256([]byte(address))

	SHAPublicKeyHex := hex.EncodeToString(shaAddress[:])

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

func (c *Network) FlatListRandom() []string {
	result := make([]string, 0)

	c.mtx.Lock()
	mapOfAddresses := make(map[string]bool)
	for _, r := range c.Ranges {
		for _, h := range r.Hosts {
			mapOfAddresses[h.Address] = true
		}
	}
	for h, _ := range mapOfAddresses {
		result = append(result, h)
	}
	c.mtx.Unlock()

	// Randomize
	rnd := make([]byte, len(result))
	rand.Read(rnd)
	sort.Slice(result, func(i, j int) bool {
		return rnd[i] < rnd[j]
	})

	return result
}

func (c *Network) GetLocalPrefixes() []string {
	prefixes := make([]string, 0)
	localIPs := c.GetLocalIPs()
	for _, r := range c.Ranges {
		for _, h := range r.Hosts {
			for _, ip := range localIPs {
				if strings.Contains(h.Address, ip) {
					prefixes = append(prefixes, r.Prefix)
				}
			}
		}
	}
	return prefixes
}

func (c *Network) GetLocalIPs() (result []string) {
	result = make([]string, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err == nil {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				result = append(result, ip.String())
			}
		}
	}
	return
}