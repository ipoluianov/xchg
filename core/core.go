package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/ipoluianov/xchg/config"
)

type Core struct {
	mtx              sync.Mutex
	config           config.Config
	listenersByAddr  map[string]*Listener
	listenersByIndex map[uint64]*Listener
	//calls            map[uint64]*Transaction

	nextListenerId    uint64
	nextTransactionId uint64

	stopPurgeRoutineCh chan struct{}
	stopStatRoutineCh  chan struct{}

	serverSecret []byte

	lastStatisticsTick time.Time
	lastStatistics     Statistics

	statistics Statistics
}

type CoreStat struct {
	ErrorsWrongFunction int64 `json:"errors_wrong_function"`

	RateCall  float64 `json:"rate_call"`
	RatePing  float64 `json:"rate_ping"`
	RateInfo  float64 `json:"rate_info"`
	RatePull  float64 `json:"rate_pull"`
	RatePut   float64 `json:"rate_put"`
	RateInit1 float64 `json:"rate_init1"`
	RateInit2 float64 `json:"rate_init2"`
}

const (
	FunctionCodeInit1 = byte(0x00)
	FunctionCodeInit2 = byte(0x01)
	FunctionCodePull  = byte(0x02)
	FunctionCodePut   = byte(0x03)
	FunctionCodeCall  = byte(0x04)
	FunctionCodePing  = byte(0x05)
	FunctionCodeNop   = byte(0x06)
)

func NewCore(conf config.Config) *Core {
	var c Core
	c.config = conf
	c.listenersByAddr = make(map[string]*Listener)
	c.listenersByIndex = make(map[uint64]*Listener)
	c.serverSecret = make([]byte, 32)
	c.lastStatisticsTick = time.Now()
	//c.calls = make(map[uint64]*Transaction)
	_, _ = rand.Read(c.serverSecret)
	return &c
}

func (c *Core) Start() {
	// sweeper
	c.stopPurgeRoutineCh = make(chan struct{})
	c.stopStatRoutineCh = make(chan struct{})
	go c.purgeRoutine()
	go c.statRoutine()
}

func (c *Core) Stop() {
	close(c.stopPurgeRoutineCh)
}

func (c *Core) calcAddrKey(publicKey []byte) []byte {
	addrSecretForSHA := make([]byte, len(c.serverSecret)+len(publicKey))
	copy(addrSecretForSHA, c.serverSecret)
	copy(addrSecretForSHA[len(c.serverSecret):], publicKey)
	addrSecretCalculated := sha256.Sum256(addrSecretForSHA)
	return addrSecretCalculated[:]
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
		for lid, l := range c.listenersByIndex {
			if time.Now().Sub(l.LastGetDT()) > time.Duration(c.config.Core.KeepDataTimeMs)*time.Millisecond {
				//logger.Println("purging", lid, l.publicKey)
				delete(c.listenersByIndex, lid)
				delete(c.listenersByAddr, string(l.publicKey))
			}
		}
		c.mtx.Unlock()
	}
}

func (c *Core) statRoutine() {
	ticker := time.NewTicker(1000 * time.Millisecond)
	for {
		select {
		case <-c.stopPurgeRoutineCh:
			return
		case <-ticker.C:
		}

		c.mtx.Lock()
		duration := time.Now().Sub(c.lastStatisticsTick)

		c.statistics.Core.RateCall = float64(c.statistics.Call.Received-c.lastStatistics.Call.Received) / duration.Seconds()
		c.statistics.Core.RatePing = float64(c.statistics.Ping.Received-c.lastStatistics.Ping.Received) / duration.Seconds()
		c.statistics.Core.RateInfo = float64(c.statistics.Info.Received-c.lastStatistics.Info.Received) / duration.Seconds()
		c.statistics.Core.RatePull = float64(c.statistics.Pull.Received-c.lastStatistics.Pull.Received) / duration.Seconds()
		c.statistics.Core.RatePut = float64(c.statistics.Put.Received-c.lastStatistics.Put.Received) / duration.Seconds()
		c.statistics.Core.RateInit1 = float64(c.statistics.Init1.Received-c.lastStatistics.Init1.Received) / duration.Seconds()
		c.statistics.Core.RateInit2 = float64(c.statistics.Init2.Received-c.lastStatistics.Init2.Received) / duration.Seconds()

		c.lastStatistics = c.statistics
		c.lastStatisticsTick = time.Now()
		c.mtx.Unlock()
	}
}

func (c *Core) ProcessFrame(ctx context.Context, data []byte) (result []byte, err error) {
	if len(data) < 1 {
		return
	}

	functionCode := data[0]
	data = data[1:]

	// Executing function
	switch functionCode {
	case FunctionCodeInit1:
		result, err = c.Init1(ctx, data)
	case FunctionCodeInit2:
		result, err = c.Init2(ctx, data)
	case FunctionCodePull:
		result, err = c.Pull(ctx, data)
	case FunctionCodePut:
		err = c.Put(ctx, data)
	case FunctionCodeCall:
		result, err = c.Call(ctx, data)
	case FunctionCodePing:
		result, err = c.Ping(ctx, data)
	case FunctionCodeNop:
		// NOP, for pinging server
	default:
		c.mtx.Lock()
		c.statistics.Core.ErrorsWrongFunction++
		c.mtx.Unlock()
		err = errors.New("wrong function")
	}
	return
}
