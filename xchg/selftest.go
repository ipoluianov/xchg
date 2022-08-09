package xchg

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ipoluianov/gomisc/crypt_tools"
)

func GenerateKeys() {
	privateKey1, _ := crypt_tools.GenerateRSAKey()
	privateKey2, _ := crypt_tools.GenerateRSAKey()

	privateKey1BS := crypt_tools.RSAPrivateKeyToDer(privateKey1)
	privateKey2BS := crypt_tools.RSAPrivateKeyToDer(privateKey2)
	publicKey1BS := crypt_tools.RSAPublicKeyToDer(&privateKey1.PublicKey)
	publicKey2BS := crypt_tools.RSAPublicKeyToDer(&privateKey2.PublicKey)

	fmt.Println("KEY1-PRIVATE", base58.Encode(privateKey1BS))
	fmt.Println()
	fmt.Println("KEY1-PUBLIC", base58.Encode(publicKey1BS))
	fmt.Println()

	fmt.Println("KEY2-PRIVATE", base58.Encode(privateKey2BS))
	fmt.Println()
	fmt.Println("KEY2-PUBLIC", base58.Encode(publicKey2BS))
	fmt.Println()
}

func SelfTest() {
	//GenerateKeys()
	//return

	var config Config
	config.Init()

	var privateKey *rsa.PrivateKey
	privateKey, _ = crypt_tools.GenerateRSAKey()

	router := NewRouter(privateKey)
	server := NewRouterServer(config, router)
	httpServer := NewHttpServer(config, router)

	fmt.Println("--------------Press any key for start")
	fmt.Scanln()

	var err error

	router.Start()

	err = server.Start()
	if err != nil {
		return
	}

	httpServer.Start()

	fmt.Println("-------------Press any key for connect")
	fmt.Scanln()

	go Server()
	go Client()

	fmt.Println("----------------Press any key for exit")
	fmt.Scanln()

	server.Stop()
	if err != nil {
		return
	}

	router.Stop()
	if err != nil {
		return
	}

	fmt.Println("Press any key for finish")
	fmt.Scanln()

	fmt.Println("Process was finished")
}

var serverPrivateKey = "7LsR8WfToH83zUcc866zc6szVEQXq5tZ4J38h3RGQJQxmBfWqHxF4ruLBFuNvWHdHxeVg7aRqitCDavJryNmVjAmoM4EwvbvPEJsActnK7pLVRZaJbw7h2y6BU7CSETfV2AmqXW5TBdPW6skuSA4sAVp6eD2oQAJsBmHUx898ctDDL2XwFT5AzJxAo722ZzLcuJqobGcCFj1DfSGWXjtzic6huG2uPM93YcRPaVte6Q22Aspo8zyonmmsVmgNissRRR1iJKM2GMMLWmVYXMXTT5JCffu9zP8TKP576r5rLgL1d7D4FJ6fwvJHoEJt7jDU75WFNxYweQK4GErRs7FM61CjpZWxMeCWcqCKyXJwSCgq9eEnskbEHfU5NeiaaPwpTXYShch3EYrM9q7hbZ4QLTeqoAiexqE2M8oHgwXi5wHijVFdL3ff3pixDGCuTyo42QnifAKQPnFJdepEC4xZKrkiHrMYLR9J4otVZQeAQpjiRdT24rXox9goenpeHmegfEwVN4VGCiaM6F1pdNouQuPWFeVChUYUeS2XBLnkhuKWEbtSDonRfvkScxcBHpHYH5mazBdcKm91FoNHbGEqVeuZQkY6283Lztp6ZpxdkYiGs85m1ELBAV7FC7xzZfs2GiqtLmJCwY3chkHnJJeYVrwd535FthVYfuNLK58sJ2yoXrKEJRZQcZdLE8n8vEm4C9gudq5jnEAui4quuoQeKvY4LkawRbUiAJZX7fhntGhKwmAMVDGm8igfxehm81ovouAKSPBCMhuYFpdU4gWoVDKoJMRBVmxkiPHpP4GfnoGdjbMRUCAnaDaJuFuaZzJ6Ux8Z6w6ZHhDC3sEMBWUi9tQokTma2GRicwnEvmC2duECWMK82tEjAwg6BGM58ohvXPseVbcidycPen9cHGzJybv7SEwomcN2ZbXydcvofSnijX6KHUSMwKJ42CuCEbfvb5wA6WmpEqZVFaCkH3rNp3D3ceTYG1a9sYuCDFTUE63pVXFpkufA5AvSUaFCdW1a6mfDpsEXwktuHUU5wSphfUWuf5rJJffzwm5YM5Ph5B6pt6ih81HJLhWunvZp85t3wemJHVfzPYun3xmu9b5ddDKMYXjWt2BftMvYqwrRgQun5nS6PsKe2hdpVykvKaMHUcuNDceD8Ur9BAdNbPgPJT1qHPfwbwHTAFSDy7jRm41nEjuxZSPC7E6N64QtA6tx2ENyoYgbBBhUiNxTJkMjGGBE1JxtgZ7oJkTD2ufQventH87QKSRxJRMJSjYTB3SJau21GyxXeBFDLVm3kXQ5vvgG6nCHy7ujaqa7KbFz9CccXnhS3hFFJ42DJd1ihy1TnFMPMaxJ5VbsAA3y46TY91pGxRBLZS2vwveAMxbowMZDNnY6891nr1Sa94QhC5BfmAMtxY6WvXGTTGFNdKZPgJoSKJdmsJh31uyCZugTfYz4YEFxq7kSByPqwxCt7QtB7t11xnmBR6swHd1L8vyv11rZ4f376rG1TtECpcMPPkNcsVtqfPgwqjoUSbbd1Bi297N4cN7NwnZghwoYsVQEUBw57JHVo7KFvW2BzXqu5g9xmiBQ273onm4dq6RVAfrWK7wyTZjpYs92UGg2wrKgCGHQuPA"
var serverPublicKey = "4e1BUTgGBfqVX8tqh3hVGZMBAZ4NVEqRx1RxRATr6tqoanD6tNaEA9TMoeiqjgi8wAPS1kbGBWfSPuE76eVik5Kw8xJAoMAMKiq8sP9Te9WdXUMPL48qUAByM6BieANkfeL3pKmxpmtWVfFUq6oTM8envR7WJxpyWy2vuGiYscwbuPaYn9q92CHv6dKb3EBqmhChScGvF3LRxiqBhB8z6eMzeVKRTBMQYw2YKCioGDEwCimUqD7kUKUoUNKT57ne6w7YeKPyy8QzGwZpQatZewaZ33jd3Sz6ZQ1ZwFwxhcp3usX9X389tFen83xrEoMoqnZYCNpRA8cmt4N8ah8YTR7yiNJ4UpE3mqEWbFJPqBjzzUzcg"

var clientPrivateKey = "KtDCWNWgpP9sYMqC7HWrKuwqbe8px5SJhQ3DdMndLoSqxkj6ezFqRW7VUfyz5pUAWnjrzhcn7YwNmzYoLs3eh2Yu1QdHjmX1EyaVfrXeGoaidnkxgwWR36ExgPd2pSjPzaM5MKaTmye47sN7VbqDnNL24uzXyB6aNcb4MSz4ZnCfkqhGxyhx5bjiSnZqEAgkmXQj2YpbsSZkvHYt5TebxLRfn2MGUeQTLBfQqbNQUEzayYgmHW2e166duhHV63kPN3urBREkzW3fUVAehyCjKmQiNSAhB77nRd4VGJ1bdmbQ7Ly4oDBEG5KWwjqGnJ1JjfqPRgZA9sRkvjZzYnZMqmGgRrF5w55hsCBRg4K1qBFxVPUCbQ3Zuo9YZEWyhP9FAc7FryCjsGdY18uGocY1tn4Cz6fc2x5THPDi2MG3VdAfNymYd2QyXXgEiq3YYrdD2Y4Zi6ZH2e3hDhrKZRMgDek32gKU9LTHdu7LEDgXzAt5qSvSYtUGrrqfAh8J7NRx8L5ZpbknJdFwNj9MptX2u6MXJcG3TXaLbt7hGGrAfZpQ4iqTiQuByfwwaWf8R8bX984iw5YyAHx556hFbyTD9zsRjgg7pjLntQRmWtyEpLt8a3upe1CLZ6RwgwSN7cuqMd3ZWkTAk3QLR5GVrLPbhnRVegJ41X5X6Pctd512msgmZ1X7pd2SdP6ei9BLaBdHeafgPpyARE8nG4WEZF23eooAWZ1GG2T5oPPaYu41MyujfHQPxv1d7fux56pS3HwUtqaQ5JrtURzYy6BVjUjifqaQgqtdhrChnramLtNfZJUKZZWWaWisBFeiyFY5d4MweFXJTHb8XXTiPrgi726BA7MwsnVjqPZfDhwH4GgpzJ53kQGMjCvGKpD3DqPaH4mkz7cU19LYJf8jcfxWK6QhXbAqvGmK4jzYyuPh1HW4RFf1qZm124Ks7GsZLQoRQCGAjUnWNyRK34EYpNPpwCT7BwpCmvVQK71QrsNcQrqF2GAK5R7ChrueKmcLN1emcXT31x6jsHi5XbB6N5nCHcdATQJG24mJ9WXSY3U3uxT4WcdkvBZ8dJLJrpMMv9TgSBPjGwhDjyAWHDMMjsaTscyAckjFgdBo4VEyy62vHLPNBMLbWW8hB2Rj7GxieNi5R2AsShTmAeTSKkG9HM67aYpoMqtbcjc69JGohJ5FvN72Q1yDayZ6i6iZaNG7ZXbfMyN7gv9oWUtPdohuLvfD2a1WSk1SVTo7vDo2vM4DP3bu9isHZquGVaRkQN5YkoKhMefJ3mWHmdjfkdKigxXpGfGwC4B6K1nQMm9MNsR8iTXiSyRMEZGC2xxchXQ4tmN1GrNNaDnjB7obJihUERfBVZBrMCgRakm2PxPaJ7hKsQXyZuTJ1nQ8BovSsHcMdAL9RhzgeoP4FFdtYpK4iEEfSJLxt5PrkDsa5RARWQvFyb6P91B5Q1pk46Bqh9woR8Y7w8jJGgivRzWsBnKPPktzYwiTNguSJqaU6UVE3ThSZ6dogbToGcd65xbDQL5GzARjW5uDeuDCtFTTrer2HQ1rJgsZsDCotnmfKVL1qHqfw1QxSXVNVv2v2HTbNnPcfH6GkAnBRn3T4auxMfPrH3S8rrZvKXMas"
var clientPublicKey = "4e1BUTgGBfqVWiynnP2sqz8edMiRst12eMac5V5bUYvWFfcjcgdA2QrGpRCfuiPDbkgFZn7CEDkhkidKGyWJoeP3sFPjrjgqPf4GxUhv6nKwwiuzekQPtSLBaw6wN4v11PszVyF1FXnj2qAuVvs4nWXeuKWjGytCqwqwXZH2E7bUSwht1CZUoNM61ytrNbRSdsC6Y5T9bNqzLigvh3Hja6AoAKjkrSbBjQu4o5eFvuqcPq23Premi7xN6gorVoFWqX7Ydi5WQR2B3SXXB76fWHaDikGakoFMCrNUAvcNHZ9Ghx2X7S8a5SPCBfrdyaUdoKciNHQhqsEBkkcn8tB1FognhFZrtCLae1HWFXe9R44FkYKkt"

func Server() {
	ss := NewSimpleServer(serverPrivateKey)
	ss.Start()
}

func Client() {
	var err error
	s := NewSimpleClient(serverPublicKey)
	for i := 0; i < 10000; i++ {
		time.Sleep(500 * time.Millisecond)
		var bs string
		bs, err = s.Version()
		if err != nil {
			fmt.Println("ERROR", err)
		} else {
			fmt.Println("RESULT", bs)
		}

	}
	s = nil
}
