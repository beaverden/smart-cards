package payments

import (
	"encoding/json"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/payment-gateway/server-context"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/hybrid-encryption"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"net"
	"strings"
)

type Card struct {
	CardN    string
	CardDate string
	Amount   float64
}

var ValidCards []Card

func SearchValidCard(message *protocol.PaymentMessage) bool {
	for _, card := range ValidCards {
		if strings.Compare(card.CardN, message.Info.CardN) == 0 {
			if strings.Compare(card.CardDate, message.Info.CardExp) == 0 {
				if message.Info.Amount > card.Amount {
					return false
				}
				return true
			}
		}
	}
	return false
}

func handleConnection(conn net.Conn, context *server_context.PGServerContext) {
	defer conn.Close()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// 4. Recv {PM, SigM(Sid, PubKC, Amount)}_PubKPG

	var messageToPG protocol.PaymentMessageToPG
	err := hybrid_encryption.DecryptFromStream(&messageToPG, context.PGPrivateKey, decoder)
	if err != nil {
		fmt.Println(err)
		return
	}

	var decryptedPM protocol.PaymentMessage
	err = hybrid_encryption.Decrypt(&decryptedPM, messageToPG.EncryptedPM, context.PGPrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	if decryptedPM.Info.Amount == messageToPG.MInfo.Amount &&
		decryptedPM.Info.Sid == messageToPG.MInfo.Sid {
		fmt.Println("4. Amount and SID OK")
	} else {
		fmt.Println("4. Amount or SID not OK!")
		return
	}

	verification, err := signature.Verify(decryptedPM.DigitalSignature, decryptedPM.Info.PubKC, &decryptedPM.Info)
	if !verification {
		fmt.Println("PI signature did not verify")
		return
	}
	fmt.Printf("Received card data: %v\n", decryptedPM.Info.CardN)

	var pgResponse protocol.PaymentGatewayResponse
	var pgRespSigned protocol.PaymentGatewayResponseSignedFields
	if SearchValidCard(&decryptedPM) {
		pgRespSigned = protocol.PaymentGatewayResponseSignedFields{
			Resp:   "YES",
			Sid:    messageToPG.MInfo.Sid,
			Amount: decryptedPM.Info.Amount,
			NC:     decryptedPM.Info.NC}

		fmt.Println("Sending PG response YES")
		pgResponse.Sid = messageToPG.MInfo.Sid
		pgResponse.Resp = "YES"

	} else {
		pgRespSigned = protocol.PaymentGatewayResponseSignedFields{
			Resp:   "ABORT",
			Sid:    messageToPG.MInfo.Sid,
			Amount: decryptedPM.Info.Amount,
			NC:     decryptedPM.Info.NC}

		fmt.Println("Sending PG response ABORT")
		pgResponse.Sid = messageToPG.MInfo.Sid
		pgResponse.Resp = "ABORT"
	}

	pgResponse.DigitalSignature, err = signature.Sign(&pgRespSigned, context.PGPrivateKey)
	if err != nil {
		fmt.Println("Signing error", err)
		return
	}

	err = hybrid_encryption.EncryptToStream(&pgResponse, messageToPG.MInfo.PubKM, encoder)
	if err != nil {
		fmt.Println("Stream encryption error", err)
		return
	}

}

func StartTCPServer(ctx *server_context.PGServerContext) {
	go func() {
		defer ctx.WaitGroup.Done()
		ln, err := net.Listen("tcp", ctx.Config.PaymentGatewayTcp)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Listening on tcp -> localhost%s\n", ctx.Config.PaymentGatewayTcp)
		for {
			conn, _ := ln.Accept()
			fmt.Printf("Got a tcp connection: %v\n", conn.RemoteAddr())
			go handleConnection(conn, ctx)
		}
	}()

}
