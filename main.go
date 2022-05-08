package main

import (
	"github.com/ipoluianov/xchg/app"
)

func main() {
	app.ServiceName = "xchg"
	app.ServiceDisplayName = "Traffic exchange service"
	app.ServiceDescription = "Traffic exchange service"
	app.ServiceRunFunc = app.RunAsServiceF
	app.ServiceStopFunc = app.StopServiceF

	if !app.TryService() {
		app.RunConsole()
	}
}
