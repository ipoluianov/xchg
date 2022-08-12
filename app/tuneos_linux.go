package app

import (
	"github.com/ipoluianov/gomisc/logger"
	"syscall"
)

func TuneFDs() {
	logger.Println("[i]", "TimeFDs", "begin")
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("[ERROR]", "TimeFDs", "syscall.Getrlimit(1) error:", err)
	}
	logger.Println("[i]", "TimeFDs", "current limits:", rLimit)
	rLimit.Max = 999999
	rLimit.Cur = 999999
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("[ERROR]", "TimeFDs", "syscall.Setrlimit error:", err)
	}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.Println("[ERROR]", "TimeFDs", "syscall.Getrlimit(2) error:", err)
	}
	var rLimit2 syscall.Rlimit
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit2)
	if err != nil {
		logger.Println("[ERROR]", "TimeFDs", "syscall.Getrlimit(3) error:", err)
	}
	logger.Println("[i]", "TimeFDs", "new limits:", rLimit2)
	logger.Println("[i]", "TimeFDs", "end")
}
