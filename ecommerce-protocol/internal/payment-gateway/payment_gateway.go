package main

import (
	"fmt"
	"crypto/dsa"
	"crypto/rand"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/http-api"
	"os"
)

var privateKey *dsa.PrivateKey

func generatePrivateKey() {
	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	privateKey = new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = *params
	err := dsa.GenerateKey(privateKey, rand.Reader) // this generates a public & private key pair
	if err != nil {
		panic(err)
	}
	//fmt.Printf("Generated Private Key: %X\n", privateKey)
}

func main() {
	fmt.Println("Starting Payment Gateway ...")
	generatePrivateKey()
	ctx := http_api.HTTPApiContext{PrivateKey: privateKey}
	http_api.StartHTTPApiHandler(&ctx)

	/*
		ln, _ := net.Listen("tcp", ":12345")

		for {
			conn, _ := ln.Accept()
			decoder := json.NewDecoder(conn)
			var message signature.SignedData
			decoder.Decode(&message)
			fmt.Println(string(message.Data))

			verification, _ := signature.Verify(message.Signature)
			if verification {
				fmt.Println("Verification OK")
			}
		}
	*/

}
