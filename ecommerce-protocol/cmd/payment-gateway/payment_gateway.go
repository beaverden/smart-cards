package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/payments"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/signing"
	"os"
	"sync"
)

func GenerateCryptoParams(context *server_context.PGServerContext) {
	privateKeyFile, err := os.Open("../../config/private/pg_private_key.pem")
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	if err != nil {
		panic(err)
	}

	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("Private Key : ", privateKeyImported)
	context.PGPrivateKey = privateKeyImported
}

func main() {
	fmt.Println("Starting Payment Gateway ...")
	var ctx server_context.PGServerContext
	ctx.Config.ReadFile("../../config/app_config.json")
	GenerateCryptoParams(&ctx)

	ctx.WaitGroup = new(sync.WaitGroup)
	ctx.WaitGroup.Add(2)

	signing.StartSignServer(&ctx)
	payments.StartTCPServer(&ctx)
	ctx.WaitGroup.Wait()

}
