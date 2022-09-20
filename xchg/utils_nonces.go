package xchg

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

type Nonces struct {
	mtx          sync.Mutex
	nonces       [][16]byte
	currentIndex int
	complexity   byte
}

func NewNonces(size int) *Nonces {
	var c Nonces
	c.complexity = 0
	c.nonces = make([][16]byte, size)
	for i := 0; i < size; i++ {
		c.fillNonce(i)
	}
	c.currentIndex = 0
	return &c
}

func (c *Nonces) fillNonce(index int) {
	if index >= 0 && index < len(c.nonces) {
		binary.LittleEndian.PutUint32(c.nonces[index][:], uint32(index)) // Index of nonce for search
		c.nonces[index][4] = c.complexity                                // Current Complexity
		rand.Read(c.nonces[index][5:])                                   // Random Nonce
	}
}

func (c *Nonces) Next() [16]byte {
	var result [16]byte
	c.mtx.Lock()
	c.fillNonce(c.currentIndex)
	result = c.nonces[c.currentIndex]
	c.currentIndex++
	if c.currentIndex >= len(c.nonces) {
		c.currentIndex = 0
	}
	c.mtx.Unlock()
	return result
}

func (c *Nonces) Check(nonce []byte) bool {
	result := true
	c.mtx.Lock()
	index := int(binary.LittleEndian.Uint32(nonce[:]))
	if index >= 0 && index < len(c.nonces) {
		for i := 0; i < 16; i++ {
			if c.nonces[index][i] != nonce[i] {
				result = false
				break
			}
		}
	} else {
		result = false
	}
	if result {
		c.fillNonce(index)
	}
	c.mtx.Unlock()
	return result
}
