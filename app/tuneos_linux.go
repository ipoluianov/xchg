package app

import (
	"github.com/ipoluianov/gomisc/logger"
	"syscall"
)

func TuneFDs() {
	logger.Println("TimeFDs begin")
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("TuneFDs Getrlimit1 error: ", err)
	}
	logger.Println("Current limits:", rLimit)
	rLimit.Max = 999999
	rLimit.Cur = 999999
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("TuneFDs Setrlimit error: ", err)
	}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("TuneFDs Getrlimit2 error: ", err)
	}
	logger.Println("TimeFDs end")
}
