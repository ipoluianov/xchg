package xchg

type DefaultLogger struct {
}

func NewDefaultLogger() *DefaultLogger {
	var c DefaultLogger
	return &c
}

func (c *DefaultLogger) Println(args ...interface{}) {

}
