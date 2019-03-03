package main

import (
	"crypto/dsa"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/http-api"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/tcp-server"
	"github.com/tkanos/gonfig"
	"sync"
)

var privateKey *dsa.PrivateKey
var portConfig config.PortConfig

func main() {
	fmt.Println("Starting Payment Gateway ...")
	privateKey, err := signature.GenerateDSAKeyPair()
	if err != nil {
		panic(err)
	}

	gonfig.GetConf("../../config/app_ports.json", &portConfig)
	var ctx server_context.PGServerContext
	ctx.PGPrivateKey = privateKey
	ctx.HttpPort = portConfig.PaymentGatewayHttp
	ctx.TcpPort = portConfig.PaymentGatewayTcp
	ctx.WaitGroup = new(sync.WaitGroup)
	ctx.WaitGroup.Add(2)

	http_api.StartHTTPApiHandler(&ctx)
	tcp_server.StartTCPServer(&ctx)
	ctx.WaitGroup.Wait()

}
