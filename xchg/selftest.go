package xchg

import (
	"fmt"
)

func SelfTest() {
	var config Config
	config.Init()

	router := NewRouter()
	server := NewRouterServer(config, router)

	fmt.Println("Press any key for start")
	fmt.Scanln()

	var err error

	router.Start()

	err = server.Start()
	if err != nil {
		return
	}

	fmt.Println("Press any key for exit")
	fmt.Scanln()

	server.Stop()
	if err != nil {
		return
	}

	router.Stop()
	if err != nil {
		return
	}

	fmt.Println("Process was finished")
}
