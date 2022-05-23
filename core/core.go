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

	statReceivedWriteBytes    int
	statReceivedWriteRequests int
	statReceivedReadBytes     int
	statReceivedReadRequests  int
	statReceivedPingBytes     int
	statReceivedPingRequests  int
	statReceivedInfoBytes     int
	statReceivedInfoRequests  int
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

func (c *Core) Read(ctx context.Context, address string, timeout time.Duration) (message *Message, err error) {
	// find core
	listenerFound := false
	var l *Listener
	c.mtx.Lock()
	l, listenerFound = c.listeners[address]
	if !listenerFound {
		l = NewListener(address)
		c.listeners[address] = l
	}
	c.statReceivedReadRequests++
	c.mtx.Unlock()

	var valid bool

	waitingDurationInMilliseconds := timeout.Milliseconds()
	waitingTick := int64(100)
	waitingIterationCount := waitingDurationInMilliseconds / waitingTick

	for i := int64(0); i < waitingIterationCount; i++ {
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

	if message != nil {
		c.mtx.Lock()
		c.statReceivedReadBytes += len(message.Data)
		c.mtx.Unlock()
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
	c.statReceivedWriteBytes += len(data)
	c.statReceivedWriteRequests++
	c.mtx.Unlock()

	// push message
	if listenerFound && listener != nil {
		err = listener.PushMessage(data)
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

	//c.statReceivedPingBytes = 0
	c.statReceivedPingRequests++

	c.mtx.Unlock()
	return
}

type Info struct {
	DT            time.Time `json:"dt"`
	ListenerCount int       `json:"lc"`

	StatReceivedWriteBytes    int `json:"stat_received_write_bytes"`
	StatReceivedWriteRequests int `json:"stat_received_write_requests"`
	StatReceivedReadBytes     int `json:"stat_received_read_bytes"`
	StatReceivedReadRequests  int `json:"stat_received_read_requests"`
	StatReceivedPingBytes     int `json:"stat_received_ping_bytes"`
	StatReceivedPingRequests  int `json:"stat_received_ping_requests"`
	StatReceivedInfoBytes     int `json:"stat_received_info_bytes"`
	StatReceivedInfoRequests  int `json:"stat_received_info_requests"`
}

func (c *Core) Info(_ context.Context) (info Info, err error) {
	c.mtx.Lock()
	info.DT = time.Now()
	info.ListenerCount = len(c.listeners)
	info.StatReceivedWriteBytes = c.statReceivedWriteBytes
	info.StatReceivedWriteRequests = c.statReceivedWriteRequests
	info.StatReceivedReadBytes = c.statReceivedReadBytes
	info.StatReceivedReadRequests = c.statReceivedReadRequests
	info.StatReceivedPingBytes = c.statReceivedPingBytes
	info.StatReceivedPingRequests = c.statReceivedPingRequests
	info.StatReceivedInfoBytes = c.statReceivedInfoBytes
	info.StatReceivedInfoRequests = c.statReceivedInfoRequests
	c.statReceivedInfoRequests++
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
			if time.Now().Sub(l.LastGetDT()) > time.Duration(c.config.Core.KeepDataTimeMs)*time.Millisecond {
				logger.Println("purging", id)
				delete(c.listeners, id)
			}
		}

		c.mtx.Unlock()
	}
}
