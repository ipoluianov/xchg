package core

import (
	"errors"
	"fmt"
	"sync"
)

type SnakeCounter struct {
	mtx           sync.Mutex
	size          int
	data          []byte
	lastProcessed int
}

func NewSnakeCounter(size int, initValue int) *SnakeCounter {
	var c SnakeCounter
	c.size = size
	c.lastProcessed = -1
	c.data = make([]byte, size)
	for i := 0; i < c.size; i++ {
		c.data[i] = 1
	}
	c.TestAndDeclare(initValue)
	return &c
}

func (c *SnakeCounter) TestAndDeclare(counter int) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if counter < c.lastProcessed-len(c.data) {
		return errors.New("too less")
	}

	if counter > c.lastProcessed {
		shiftRange := counter - c.lastProcessed
		newData := make([]byte, c.size)
		for i := 0; i < len(c.data); i++ {
			b := byte(0)
			oldAddressOfCell := i - shiftRange
			if oldAddressOfCell >= 0 && oldAddressOfCell < len(c.data) {
				b = c.data[oldAddressOfCell]
			}
			newData[i] = b
		}
		c.data = newData
		c.data[0] = 1
		c.lastProcessed = counter
		return nil
	}

	index := c.lastProcessed - counter
	if index >= 0 && index < c.size {

		if c.data[index] == 0 {
			c.data[c.lastProcessed-counter] = 1
			return nil
		}
	}

	return errors.New("already used")
}

func (c *SnakeCounter) LastProcessed() int {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.lastProcessed
}

func (c *SnakeCounter) Print() {
	fmt.Println("--------------------")
	fmt.Println("Header:", c.lastProcessed)
	for i, v := range c.data {
		fmt.Println(c.lastProcessed-i, v)
	}
	fmt.Println("--------------------")
}
