package core

import (
	"context"
	"errors"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/config"
	"sync"
	"time"
)

type Core struct {
	mtx                sync.Mutex
	config             config.Config
	listeners          map[string]*Listener
	stopPurgeRoutineCh chan struct{}
}

func NewCore(conf config.Config) *Core {
	var c Core
	c.config = conf
	c.listeners = make(map[string]*Listener)
	return &c
}

func (c *Core) Start() {
	// sweeper
	c.stopPurgeRoutineCh = make(chan struct{})
	go c.purgeRoutine()
}

func (c *Core) Stop() {
	close(c.stopPurgeRoutineCh)
}

func (c *Core) Read(ctx context.Context, address string) (message *Message, err error) {
	// find core
	listenerFound := false
	var l *Listener
	c.mtx.Lock()
	l, listenerFound = c.listeners[address]
	if !listenerFound {
		l = NewListener(address)
		c.listeners[address] = l
	}
	c.mtx.Unlock()

	var valid bool

	waitingDurationInMilliseconds := 10000
	waitingTick := 100
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	for i := 0; i < waitingIterationCount; i++ {
		message, valid = l.Pull()
		if ctx.Err() != nil {
			break
		}

		if !valid {
			time.Sleep(time.Duration(waitingTick) * time.Millisecond)
			continue
		}
		break
	}

	if !valid {
		err = errors.New("no data")
	}
	return
}

func (c *Core) Write(_ context.Context, address string, data []byte) (err error) {
	// find core
	listenerFound := false
	var listener *Listener
	c.mtx.Lock()
	listener, listenerFound = c.listeners[address]
	c.mtx.Unlock()

	// push message
	if listenerFound && listener != nil {
		err = listener.PushMessage([]byte(data))
	} else {
		err = errors.New("no route to host")
	}
	return
}

func (c *Core) Ping(_ context.Context, address string) (listenerInfo string, err error) {
	var l *Listener
	listenerFound := false
	c.mtx.Lock()
	l, listenerFound = c.listeners[address]
	if !listenerFound {
		err = errors.New("no route to host")
	} else {
		listenerInfo = l.LastGetDT().String()
	}
	c.mtx.Unlock()
	return
}

type Info struct {
	DT            time.Time `json:"dt"`
	ListenerCount int       `json:"lc"`
}

func (c *Core) Info(_ context.Context) (info Info, err error) {
	c.mtx.Lock()
	info.DT = time.Now()
	info.ListenerCount = len(c.listeners)
	c.mtx.Unlock()
	return
}

func (c *Core) purgeRoutine() {
	ticker := time.NewTicker(time.Duration(c.config.Core.PurgeIntervalMs) * time.Millisecond)
	for {
		select {
		case <-c.stopPurgeRoutineCh:
			return
		case <-ticker.C:
		}

		c.mtx.Lock()
		for id, l := range c.listeners {
			if time.Now().Sub(l.LastGetDT()) > 10*time.Second {
				logger.Println("purging", id)
				delete(c.listeners, id)
			}
		}

		logger.Println("statistics. count:", len(c.listeners))

		c.mtx.Unlock()
	}
}
