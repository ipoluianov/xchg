package main

import (
	"fmt"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func main() {
	serverPrivateKey, _ := xchg.GenerateRSAKey()
	server := xchg_samples.NewSimpleServer(serverPrivateKey)
	server.Start()

	serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)

	count := 0
	errs := 0

	fn := func() {
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

	for i := 0; i < 100; i++ {
		time.Sleep(1 * time.Millisecond)
		go fn()
	}

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
