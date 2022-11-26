package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_samples"
)

func ttt() {
	privateKey, _ := xchg.GenerateRSAKey()
	privateKeyBS, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKeyBS, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	privateKeyBS64 := base64.StdEncoding.EncodeToString(privateKeyBS)
	fmt.Println("private:", privateKeyBS64)
	publicKeyBS64 := base64.StdEncoding.EncodeToString(publicKeyBS)
	fmt.Println("public:", publicKeyBS64)
}

func ttt2() {
	privateKeyBS64 := "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4T69E5NAQjf8yZDe1spPizbGkgmqYxr+0ry3NIYNkkpfa4GpwP5FFeg8/Zk22SNHqFy9txMkwVfxATLj2tB/BcqqjhUxq85unQlGxAyYatsy5VcxOronqizNjjd37/MEOHW7V3anK0sHes+BGat/2t10tZFWhP+KNF4l0D2SusmZ+iD/C+Yv8UAFtWAk9zpcUY6MnGm0Tv/FCVkiwbaUDwfz29meQnbse24iRxgRPQ7F1TLiLInir4savKD555hPTAEFIjd0Jetv3RUyF4qaRjko8bfe7F0GSXtQtIimu3+5oaroxKxg3W9RFr3BKVmGc1AD2LHNHYSER3L9NhUR1AgMBAAECggEAJWxwnyGCqcnbRmUY9rjC1GuFpWyhrlG0vUBQoXUrk7E8SkIE+rO9kIjfLbVdFCUnEkwQ4k3xt/HNnVS2vckHJaVdxoQbZx/9u/F4WuPTydrSKNOl/1frQwdusMkuiKrinDYXui8e+cLfgJOvdzzeKt9CeSQFSw+ItbNQwpMZk2rnho6iTMPXiiKj6pfec7I2miNUFHQEWt698fFaLzmKc/qSTAmlBQyiiFQNsP1dieMXboV23gLaH4tVwoRsVgM6V6HAyhIbyNHzqGRXJB6uasytnrcSBLb646WepLnskpgBg+VZjBgE3r7PMoJ7raQBViD9Zyz4DVGZbzB315cVwQKBgQDLyE9GyfB4vqgj863puVjlgnhBFmcZops7yI469UuwGd5WQ9tErn9Tx0LrSk8/PQIkOAHwit8F2UNlQEjq1HWOXWjI0wu67okOs8ax8a5gOIistBKfezK08SyIy2HXi9dKU673pasx5vamDhpm3wis3LP3/KLhrw0Wfjhy+bOF0QKBgQDnihtUXWW4MBbn5dMeUFTKefgw/kmxnTc9FyR9YJDBJ0b4vOsi6I0HuuQzOCFS3qXLdmlmkhfGk8089fBWAQ8rlQZUvMl9XyX3T7EEL8kIKUpnAS1o1jzb/ls1RU5735L/ngSzr0V5fT7Da74WSXhRk3esUkZserpLx0JbXtMpZQKBgQCWrGf5dkyoaogV9RHtE49oO1zA+1iF+tX+kR6g90fcUHQ1onyYvtEEV/vhzxLjNi/EKek9OuEGCQus7Kg9gZPeDLDydCFjOQX76e8LGSCOop5j2809QDFQ2lXMW1zfq9UmbtOa5lK7VgOe6iSZVWWrspAa1yBz8COkMvV4Baq4UQKBgCDuQo7QLcxxgoB+7nTsRfL6P/Nv5zlMu/ODXBw85LmkBXMRI3w2iQBlc1lZjVvE8N2sPLdq5djHYrRd4k3JHsg7DMh2hU3Af5zaB7optbTkcoGN6FB1z/gWCBDeh5gUp0qVxeNsdTwfNRMEOufekS9BAw9OMFfzaJWohGaMaQoFAoGBAMuwwMYAhUuMcAHuhzy52/KBYcSLcqigsrrQzgdj3x8X/CZuFvez1ErBbgn+IjVgx3teZfRVzsvblEOo4yrohkMPfmWTgH1AHNSTDeBnPsw3lzrk+DdWDYCiUWkgRr+tEIJF7KMreNHvR5bK7is7UFowd9FcOGnPe8aN/Ww4H+Px"
	publicKeyBS64 := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuE+vROTQEI3/MmQ3tbKT4s2xpIJqmMa/tK8tzSGDZJKX2uBqcD+RRXoPP2ZNtkjR6hcvbcTJMFX8QEy49rQfwXKqo4VMavObp0JRsQMmGrbMuVXMTq6J6oszY43d+/zBDh1u1d2pytLB3rPgRmrf9rddLWRVoT/ijReJdA9krrJmfog/wvmL/FABbVgJPc6XFGOjJxptE7/xQlZIsG2lA8H89vZnkJ27HtuIkcYET0OxdUy4iyJ4q+LGryg+eeYT0wBBSI3dCXrb90VMheKmkY5KPG33uxdBkl7ULSIprt/uaGq6MSsYN1vURa9wSlZhnNQA9ixzR2EhEdy/TYVEdQIDAQAB"
	privateKeyBS, _ := base64.StdEncoding.DecodeString(privateKeyBS64)
	publicKeyBS, _ := base64.StdEncoding.DecodeString(publicKeyBS64)
	privateKeyAny, _ := x509.ParsePKCS8PrivateKey(privateKeyBS)
	publicKeyAny, _ := x509.ParsePKIXPublicKey(publicKeyBS)
	privateKey := privateKeyAny.(*rsa.PrivateKey)
	publicKey := publicKeyAny.(*rsa.PublicKey)
	fmt.Println(privateKey)
	fmt.Println(publicKey)

	privateKeyHash := sha256.Sum256(privateKeyBS)
	publicKeyHash := sha256.Sum256(publicKeyBS)

	fmt.Println("privateKeyHash", privateKeyHash)
	fmt.Println("publicKeyHash", publicKeyHash)

	data := make([]byte, 3)
	data[0] = 42
	data[1] = 43
	data[2] = 44

	hash := sha256.Sum256(data)
	signatureBS, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: 32,
	})
	fmt.Println("hash", hash)
	if err != nil {
		fmt.Println("ERROR signature", err)
		return
	}

	signatureBS64 := base64.StdEncoding.EncodeToString(signatureBS)
	fmt.Println("SIGNATURE:", signatureBS64)

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signatureBS, &rsa.PSSOptions{
		SaltLength: 32,
	})

	fmt.Println("VERIFY:", err)
}

func rrr() {
	block, err := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIFowIBAAKCAQEAts0ysLt9nx953i9dNziFugE7MEqacBijJvIH4OY8j5c93NCOZpYn2bZ9eIin7xGaO1Zhtpez2xWP7WYBR6wZPjmxG1mY52lVWtpCiVDpY1f5Oz3Q8ENgUJpu1nMCwRPIysTu6YIfv2CsuMteLwg74dVUUViGJ/N2kYz2cuzJKAbnlxDSHbn7p2Ut5viAKH7IU2FPh2kvpKd10hlNC5iDRd+IPnGePEF1jFXKRBYf1iaV053tvdMw8J40skrCsYw16jcCyo+dulLLoEHntxuzhRkh8p2C2SaCkr8rw4KkMIsDVsI+cF9HHFl9Zd6pxi0i0DRdNjTGHpEcwS64tdyypwKCAQEAjPwLmVSxGTVcd2kOOpWkRYXHkYIoREYsJtBKFUFc+d3Kf3B2M1ahm37snDbBVle8HQGNURcFRvYFUDH40L9BpMU3/AEJNYj+pJhq8p7tsYnbFb6iU3uTX/cLfueq+yB4HzLtlDigpag47jkjBaETFiTC6A4fQda63pzaQl6u8ee7bdj33PR9V7PbejqQIxZPz4h94lMcKjwh8Oai8WpnuSJjniX8tV2L4FpLpgduGe3yloeqMt2PHyC9zUcIhCjq1ByhyZx/heWjiU9v/n8B/dy6yykyWJorrZm/R9CuHfzNqKJTxHotXm83zYI4b/jUsozUFZyzThFqKmn+u63PyQKCAQEAjPwLmVSxGTVcd2kOOpWkRYXHkYIoREYsJtBKFUFc+d3Kf3B2M1ahm37snDbBVle8HQGNURcFRvYFUDH40L9BpMU3/AEJNYj+pJhq8p7tsYnbFb6iU3uTX/cLfueq+yB4HzLtlDigpag47jkjBaETFiTC6A4fQda63pzaQl6u8ee7bdj33PR9V7PbejqQIxZPz4h94lMcKjwh8Oai8WpnuSJjniX8tV2L4FpLpgduGe3yloeqMt2PHyC9zUcIhCjq1ByhyZx/heWjiU9v/n8B/dy6yykyWJorrZm/R9CuHfzNqKJTxHotXm83zYI4b/jUsozUFZyzThFqKmn+u63PyQKBgQDgvlr7jKDgMl79ZtSUkPbi8L36tNWdyxHo3JuueV0umhojHZS/MWNTQlDiQN4EXa8nfs8y9lGCCafVIXZ8ybaeRE0z8KB13JUeItpBDGkYrpDdr24+QKyKveilgH6eJMncigBVQpmGTssJARhGaBZY57F4Fr/EJw/O1ssFsHcGiwKBgQDQOY/1xCy7WLx9oHVkBPAw12Up+GPlvILBGIQRVDym5nYaFKIgHPaCcyeQjqCRaaBd+YIe9ARn1agcyplcRVAj4xQYMDOOGiNFK6oQa4ZFLYWDXYGk7dNitwOq5cxjH5GA91UKhCm2cooFkoE+bdQ74mprMNh4dCqRjoiV3/Xj1QKBgCkGNl9ypS8norVI3wcbiyWT4mnwNoouNl+2XWi02LCYCqtcS/m2jzX0hgU26BAN9doUyMe5tNky4AMEr7dJrt8nApy3kOLS2Bl/LS3wkQKjYuhEjLAqaBSPY/dKBFLjzkFGo5bsqE+e9Gr5WzAG8gVajcepB2pL4xPTm423T5LPAoGAcvOUOgV2/GZciK4QoIrpXs1KmAT8gVO0i41RO4/Ze/o2sOc7KadTn2ibKv7SPfSmB7s6zoO/+uLE0EA4sevB9k3iRgg2LfjYB9O3KyFxGreqwX7Zl4eD7zdB2xLJ5t8CoMPqOsgDjylkcPcUSravN/Ai99Ibb0QSTBD37mWZhZECgYBF0hM7Z69vvjxSCU8PbJVapRy6/lUT72RndKli3VjZKApicdyCgFGMpM8L+uwLOB2Eu2hItXMH6rwRJshIsZGB7SkUbS75367qDebRKhTAqli6MiqW+hoVdMdRDdysTrK4Xt9ZRxuB3PwBWPGMNBqcRQOUMHv4laKROOJJ7IDvug==
-----END RSA PRIVATE KEY-----`))
	fmt.Println(err)
	fmt.Println(block.Type)
}

func main() {
	rrr()
	return
	//ttt()
	//ttt2()
	//	return

	count := 0
	errs := 0

	fn := func() {
		serverPrivateKey, _ := xchg.GenerateRSAKey()
		server := xchg_samples.NewSimpleServer(serverPrivateKey)
		server.Start()

		serverAddress := xchg.AddressForPublicKey(&serverPrivateKey.PublicKey)
		fmt.Println(serverAddress)
		//client := xchg_samples.NewSimpleClient(serverAddress)

		for {
			time.Sleep(50 * time.Millisecond)
			/*var err error
			fmt.Println("processing ...")
			res, err := client.Version()
			if err != nil {
				fmt.Println("RESULT: error:", err)
				errs++
			} else {
				count++
				fmt.Println(res)
				fmt.Println("================== RESULT OK ================")
			}*/
		}
	}

	/*go func() {
		for i := 0; i < 1; i++ {
			time.Sleep(200 * time.Millisecond)
			go fn()
		}
	}()*/

	fn()

	for {
		time.Sleep(1 * time.Second)
		fmt.Println("res:", count, errs)
		count = 0
		errs = 0
	}
}
