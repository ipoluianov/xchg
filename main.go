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

		client := xchg_samples.NewSimpleClient(serverAddress)

		for {
			_, err := client.Version()
			if err != nil {
				//fmt.Println("RESULT: error:", err)
				errs++
			} else {
				count++
				//fmt.Println("RESULT OK")
			}
			time.Sleep(1 * time.Millisecond)
		}
	}

	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		go fn()
	}

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
