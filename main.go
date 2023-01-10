package main

import (
	"fmt"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func main() {
	count := 0
	errs := 0

	fn := func() {
		serverPrivateKey, _ := xchg.GenerateRSAKey()
		server := xchg_samples.NewSimpleServer(serverPrivateKey)
		server.Start()

		serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
		fmt.Println(serverAddress)
		client := xchg_samples.NewSimpleClient(serverAddress)

		for {
			time.Sleep(50 * time.Millisecond)
			var err error
			_, err = client.Version()
			if err != nil {
				errs++
			} else {
				count++
			}
		}
	}

	go fn()

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
