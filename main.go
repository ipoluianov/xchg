package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

var cc1 = 0

func aaa() {
	for {
		httpClient := &http.Client{}
		httpClient.Timeout = 1 * time.Second
		_, err := httpClient.Get("http://x01.gazer.cloud:8084/api/0")
		if err != nil {
			//fmt.Println("Error:", err)
		} else {
			cc1++
		}
	}
}

func main() {
	for i := 0; i < 100; i++ {
		go aaa()
	}

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", cc1)
		cc1 = 0
	}

	count := 0
	errs := 0

	fn := func() {
		serverPrivateKey, _ := xchg.GenerateRSAKey()
		server := xchg_samples.NewSimpleServer(serverPrivateKey)
		server.Start()

		serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
		client := xchg_samples.NewSimpleClient(serverAddress)

		for {
			//time.Sleep(1 * time.Millisecond)
			_, err := client.Version()
			if err != nil {
				fmt.Println("RESULT: error:", err)
				errs++
			} else {
				count++
				//fmt.Println("================== RESULT OK ================")
			}
		}
	}

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		go fn()
	}

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
