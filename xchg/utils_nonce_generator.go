package xchg

import (
	"encoding/binary"
	"math/rand"
	"sync"
)

type NonceGenerator struct {
	mtx          sync.Mutex
	nonces       []uint64
	currentIndex int
}

func NewNonceGenerator(size int) *NonceGenerator {
	var c NonceGenerator
	c.init(size)
	return &c
}

func (c *NonceGenerator) Init(size int) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.init(size)
}

func (c *NonceGenerator) init(size int) {
	if size < 1 {
		size = 1
	}
	c.nonces = make([]uint64, size)
	bs := make([]byte, 8)
	for i := 0; i < len(c.nonces); i++ {
		rand.Read(bs)
		n := binary.LittleEndian.Uint64(bs)
		for n == 0 { // 0 - is not allowed
			rand.Read(bs)
			n = binary.LittleEndian.Uint64(bs)
		}
		c.nonces[i] = n
	}
	c.currentIndex = 0
}

func (c *NonceGenerator) Get() []byte {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.currentIndex++
	if c.currentIndex >= len(c.nonces) {
		c.Init(len(c.nonces))
	}
	result := c.nonces[c.currentIndex]
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce[:], uint64(c.currentIndex))
	binary.LittleEndian.PutUint64(nonce[8:], result)
	return nonce
}

func (c *NonceGenerator) Check(nonceBytes []byte) bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	indexUint64 := binary.LittleEndian.Uint64(nonceBytes[0:])
	if indexUint64 > 0x7FFFFFFF {
		return false
	}
	indexInt := int(indexUint64)
	nonce := binary.LittleEndian.Uint64(nonceBytes[8:])
	if int(indexInt) < 0 || int(indexInt) >= len(c.nonces) {
		return false
	}

	if c.nonces[indexInt] == nonce {
		c.nonces[indexInt] = 0
		return true
	}
	return false
}
