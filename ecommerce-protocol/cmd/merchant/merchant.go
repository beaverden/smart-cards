package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	config2 "github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/hybrid-encryption"
	ecryptoSignature "github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"github.com/pkg/errors"
	rand2 "math/rand"
	"net"
)

type MerchantContext struct {
	Config       config2.AppConfig
	WebSegment   protocol.WebSegment
	RSAKey       *rsa.PrivateKey
	CustomerPubK *rsa.PublicKey
	PGPubK       *rsa.PublicKey
}

func ServeClient(conn net.Conn, context *MerchantContext) {
	defer conn.Close()
	address := fmt.Sprintf("localhost%s", context.Config.PaymentGatewayTcp)
	pgConn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pgConn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	// 0. Send Signed Web Segment
	encoder.Encode(&context.WebSegment)

	// 1. Receive public key
	context.CustomerPubK = new(rsa.PublicKey)
	err = hybrid_encryption.DecryptFromStream(context.CustomerPubK, context.RSAKey, decoder)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Received public key: %v\n", context.CustomerPubK)

	// 2. Send SID
	var sidData protocol.MerchantSid
	sidData.Sid = protocol.SID(rand2.Int())
	sidData.SidSignature, err = ecryptoSignature.Sign(&sidData.Sid, context.RSAKey)
	err = hybrid_encryption.EncryptToStream(&sidData, context.CustomerPubK, encoder)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Sent SID: %v\n", sidData.Sid)

	// 3. Receive PM, PO
	var paymentToMerchant protocol.PaymentMessageToMerchant
	err = hybrid_encryption.DecryptFromStream(&paymentToMerchant, context.RSAKey, decoder)
	if err != nil {
		fmt.Println(err)
		return
	}
	verification, err := ecryptoSignature.Verify(paymentToMerchant.PO.DigitalSignature, context.CustomerPubK, &paymentToMerchant.PO.PaymentOrder)
	if !verification {
		fmt.Println("Client signature did not verify for PO")
		return
	} else {
		fmt.Println("Client signature for PO ok")
	}

	// 4. Send PM to PG
	fmt.Printf("Received payment info for: %v\n", paymentToMerchant.PO.PaymentOrder.OrderDesc)
	var messageToPG protocol.PaymentMessageToPG
	messageToPG.EncryptedPM = paymentToMerchant.EncryptedPM
	messageToPG.MInfo.Sid = paymentToMerchant.PO.PaymentOrder.Sid
	messageToPG.MInfo.Amount = paymentToMerchant.PO.PaymentOrder.Amount
	messageToPG.MInfo.PubKC = context.CustomerPubK
	messageToPG.MInfo.PubKM = &context.RSAKey.PublicKey
	messageToPG.DigitalSignature, err = ecryptoSignature.Sign(&messageToPG.MInfo, context.RSAKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	pgEncoder := json.NewEncoder(pgConn)
	pgDecoder := json.NewDecoder(pgConn)

	err = hybrid_encryption.EncryptToStream(&messageToPG, context.PGPubK, pgEncoder)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 5. Receive response Resp
	var pgResponse protocol.PaymentGatewayResponse
	err = hybrid_encryption.DecryptFromStream(&pgResponse, context.RSAKey, pgDecoder)
	if err != nil {
		fmt.Println("Unable to get pgResponse", err)
		return
	}
	fmt.Printf("Got PG Response: %v\n", pgResponse.Resp)

	err = hybrid_encryption.EncryptToStream(&pgResponse, context.CustomerPubK, encoder)
	if err != nil {
		fmt.Println(err)
		return
	}

}

func StartTCPServer(context *MerchantContext) error {
	ln, err := net.Listen("tcp", context.Config.MerchantPort)
	if err != nil {
		panic(errors.WithStack(err))
	}
	fmt.Printf("Listening on tcp -> localhost%s\n", context.Config.MerchantPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return errors.WithStack(err)
		}
		go ServeClient(conn, context)
	}
	return nil
}

func GenerateCryptoParams(context *MerchantContext) {
	key, err := rsa.GenerateKey(rand.Reader, context.Config.RsaBits)
	if err != nil {
		panic(err)
	}
	context.RSAKey = key
	context.PGPubK = context.Config.PGPubK
}

func CreateWebSegment(context *MerchantContext) {
	context.WebSegment.MerchantInfo.Name = "Amazon"
	context.WebSegment.MerchantInfo.MerchantPubKey = &context.RSAKey.PublicKey
	context.WebSegment.Signature = new(ecryptoSignature.RSASignature)

	segmentToSign, err := json.Marshal(context.WebSegment.MerchantInfo)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost%s", context.Config.PaymentGatewaySignTcp))
	defer conn.Close()
	conn.Write(segmentToSign)

	decoder := json.NewDecoder(conn)
	err = decoder.Decode(context.WebSegment.Signature)
	if err != nil {
		panic(err)
	}
	verification, err := ecryptoSignature.Verify(context.WebSegment.Signature, context.PGPubK, segmentToSign)
	if err != nil {
		panic(err)
	}
	if !verification {
		panic("Web segment signature did not verify")
	} else {
		fmt.Println("Web segment signature OK")
	}
}

func main() {
	fmt.Println("Starting Merchant ...")
	var context MerchantContext
	context.Config.ReadFile("../../config/app_config.json")
	GenerateCryptoParams(&context)
	CreateWebSegment(&context)
	StartTCPServer(&context)

}
