package main

import (
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/internal/app"
)

func main() {
	app.ServiceName = "xchg"
	app.ServiceDisplayName = "Traffic exchange service"
	app.ServiceDescription = "Traffic exchange service"
	app.ServiceRunFunc = app.RunAsServiceF
	app.ServiceStopFunc = app.StopServiceF

	logger.Init(logger.CurrentExePath() + "/logs")

	if !app.TryService() {
		app.RunConsole()
	}
}
