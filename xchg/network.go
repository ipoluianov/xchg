package xchg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type Host struct {
	ip string
}

func newHost(ip string) *Host {
	var c Host
	c.ip = ip
	return &c
}

type Range struct {
	prefix string
	hosts  map[string]*Host
}

func newRange(prefix string) *Range {
	var c Range
	c.prefix = prefix
	c.hosts = make(map[string]*Host)
	return &c
}

func (c *Range) Hosts() []string {
	hosts := make([]string, 0, len(c.hosts))
	for _, h := range c.hosts {
		hosts = append(hosts, h.ip)
	}
	return hosts
}

type Network struct {
	ranges map[string]*Range
}

func NewNetwork() *Network {
	var c Network
	c.init()
	return &c
}

func (c *Network) init() {
	c.ranges = make(map[string]*Range)
}

func (c *Network) SetRange(prefix string, hosts []string) {
	r := newRange(prefix)
	for _, h := range hosts {
		r.hosts[h] = newHost(h)
	}
	c.ranges[prefix] = r
}

func (c *Network) Load(rawContent string) {
	rawContentBS := []byte(rawContent)
	content := make([]byte, 0, len(rawContentBS))

	// Content cleanup
	lastCharIsNewLine := false
	for _, b := range rawContentBS {
		if b > 32 {
			content = append(content, b)
			lastCharIsNewLine = false
		} else {
			if b == '\r' || b == '\n' {
				if !lastCharIsNewLine {
					content = append(content, '\n')
				}
				lastCharIsNewLine = true
			}
		}
	}

	// Get lines
	lines := strings.FieldsFunc(string(content), func(r rune) bool {
		return r == '\n'
	})

	c.init()

	for _, line := range lines {
		indexOfEq := strings.Index(line, "=")
		if indexOfEq < 0 {
			continue
		}
		rangePrefix := line[0:indexOfEq]
		rangeAddressesLine := line[indexOfEq+1:]
		addresses := strings.FieldsFunc(rangeAddressesLine, func(r rune) bool {
			return r == ';'
		})
		c.SetRange(rangePrefix, addresses)
	}

	fmt.Println("Loaded: ", c.ranges)
}

func (c *Network) Save() string {
	var builder strings.Builder
	for _, r := range c.ranges {
		var builderAddresses strings.Builder
		for _, a := range r.hosts {
			builderAddresses.WriteString(a.ip)
		}
		builder.WriteString(r.prefix + ":" + builderAddresses.String() + "\n")
	}
	return builder.String()
}

func (c *Network) GetAddressesByPublicKey(publicKeyBS []byte) []string {
	SHAPublicKeyBS := sha256.Sum256(publicKeyBS)
	SHAPublicKeyHex := hex.EncodeToString(SHAPublicKeyBS[:])

	var preferredRange *Range
	preferredRangeScore := 0

	for _, r := range c.ranges {
		rangeScore := 0
		for i := 0; i < len(SHAPublicKeyHex) && i < len(r.prefix); i++ {
			if r.prefix[i] == SHAPublicKeyHex[i] {
				rangeScore++
			}
		}
		if rangeScore == len(r.prefix) && rangeScore > preferredRangeScore {
			preferredRange = r
			preferredRangeScore = rangeScore
		}
	}

	addresses := make([]string, 0)

	if preferredRange != nil {
		addresses = append(addresses, preferredRange.Hosts()...)
	}

	if defaultRange, ok := c.ranges[""]; ok {
		addresses = append(addresses, defaultRange.Hosts()...)
	}

	return addresses
}
