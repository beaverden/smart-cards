package signing

import (
	"encoding/json"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"net"
)

func SignHandler(conn net.Conn, context *server_context.PGServerContext) {
	defer conn.Close()

	var mInfo protocol.MerchantData
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&mInfo)
	if err != nil {
		return
	}
	messageSignature, err := signature.Sign(&mInfo, context.PGPrivateKey)
	encoder := json.NewEncoder(conn)
	encoder.Encode(messageSignature)
}

func StartSignServer(context *server_context.PGServerContext) {
	go func() {
		defer context.WaitGroup.Done()
		ln, err := net.Listen("tcp", context.Config.PaymentGatewaySignTcp)
		if err != nil {
			panic(err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go SignHandler(conn, context)
		}
	}()

}
