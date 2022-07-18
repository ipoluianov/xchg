package core

type Statistics struct {
	BinServer  BinServerStat  `json:"bin_server"`
	HttpServer HttpServerStat `json:"http_server"`
	Core       CoreStat       `json:"core"`
	Info       InfoStat       `json:"info"`
	Ping       PingStat       `json:"ping"`
	Init1      Init1Stat      `json:"init1"`
	Init2      Init2Stat      `json:"init2"`
	Pull       PullStat       `json:"pull"`
	Call       CallStat       `json:"call"`
	Put        PutStat        `json:"put"`
}

type BinServerStat struct {
}

type HttpServerStat struct {
	Started          int64 `json:"started"`
	Stopped          int64 `json:"stopped"`
	Received         int64 `json:"received"`
	ErrorsLimiter    int64 `json:"errors_limiter"`
	ServiceFunctions int64 `json:"service_functions"`
	ErrorsListen     int64 `json:"errors_listen"`
}

func (c *Core) IncrementHttpServerStarted() {
	c.mtx.Lock()
	c.statistics.HttpServer.Started++
	c.mtx.Unlock()
}

func (c *Core) IncrementHttpServerStopped() {
	c.mtx.Lock()
	c.statistics.HttpServer.Stopped++
	c.mtx.Unlock()
}

func (c *Core) IncrementHttpServerReceived() {
	c.mtx.Lock()
	c.statistics.HttpServer.Received++
	c.mtx.Unlock()
}

func (c *Core) IncrementHttpServerErrorsLimiter() {
	c.mtx.Lock()
	c.statistics.HttpServer.ErrorsLimiter++
	c.mtx.Unlock()
}

func (c *Core) IncrementHttpServerServiceFunctions() {
	c.mtx.Lock()
	c.statistics.HttpServer.ServiceFunctions++
	c.mtx.Unlock()
}

func (c *Core) IncrementHttpServerErrorsListen() {
	c.mtx.Lock()
	c.statistics.HttpServer.ErrorsListen++
	c.mtx.Unlock()
}
