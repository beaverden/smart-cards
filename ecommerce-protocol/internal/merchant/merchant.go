package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	config2 "github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/hybrid-encryption"
	ecryptoSignature "github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"github.com/pkg/errors"
	"github.com/tkanos/gonfig"
	"net"
	"net/http"
)

type MerchantContext struct {
	ClientAcceptTcp    string
	PaymentGatewayTcp  string
	PaymentGatewayHttp string
	WebSegment         protocol.WebSegment
	RSAParams          *rsa.PrivateKey
}

func ServeClient(conn net.Conn, context *MerchantContext) {
	defer conn.Close()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	// 0. Send Signed Web Segment
	encoder.Encode(&context.WebSegment)

	// 1. Receive
	var clientPublicKey rsa.PublicKey
	err := hybrid_encryption.DecryptStream(&clientPublicKey, context.RSAParams, decoder)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func StartTCPServer(context *MerchantContext) error {
	ln, _ := net.Listen("tcp", context.ClientAcceptTcp)
	fmt.Printf("Listening on tcp -> localhost%s\n", context.ClientAcceptTcp)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	context.RSAParams = key
}

func CreateWebSegment(context *MerchantContext) {
	context.WebSegment.MerchantInfo.Name = "Amazon"
	context.WebSegment.MerchantInfo.MerchantPubKey = &context.RSAParams.PublicKey
	context.WebSegment.Signature = new(ecryptoSignature.DSASignature)
	segmentToSign, err := json.Marshal(context.WebSegment.MerchantInfo)
	if err != nil {
		panic(err)
	}
	resp, err := http.Post(
		fmt.Sprintf("http://localhost%s/signSegment", context.PaymentGatewayHttp),
		"application/json",
		bytes.NewReader(segmentToSign))
	if err != nil {
		panic(err)
	}

	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	err = decoder.Decode(context.WebSegment.Signature)
	if err != nil {
		panic(err)
	}
	verification, err := ecryptoSignature.Verify(context.WebSegment.Signature, segmentToSign)
	if err != nil {
		panic(err)
	}
	if !verification {
		panic("Web segment signature did not verify")
	}
}

func main() {
	fmt.Println("Starting Merchant ...")
	var config config2.PortConfig
	err := gonfig.GetConf("../../config/app_ports.json", &config)
	if err != nil {
		panic(err)
	}

	var context MerchantContext
	context.ClientAcceptTcp = config.MerchantPort
	context.PaymentGatewayTcp = config.PaymentGatewayTcp
	context.PaymentGatewayHttp = config.PaymentGatewayHttp
	GenerateCryptoParams(&context)
	CreateWebSegment(&context)
	StartTCPServer(&context)

	/*
		conn, _ := net.Dial("tcp", "localhost:12345")

		s := []byte("Hello!")

		sig, err := ecryptoSignature.Sign(s, privateKey)
		if err != nil {
			panic(err)
		}

		data := ecryptoSignature.SignedData{Data: s, Signature: sig}
		byteJson, _ := json.Marshal(data)
		fmt.Println(string(byteJson))

		encoder := json.NewEncoder(conn)
		encoder.Encode(data)
		conn.Close()
	*/
}
