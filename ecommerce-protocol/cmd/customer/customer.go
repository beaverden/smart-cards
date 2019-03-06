package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	config2 "github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/hybrid-encryption"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/pkg/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"net"
)

type SessionContext struct {
	config       config2.AppConfig
	WebSegment   protocol.WebSegment
	RsaKey       *rsa.PrivateKey
	Decoder      *json.Decoder
	Encoder      *json.Encoder
	SessionID    protocol.SID
	SessionNonce []byte

	MerchantPubK *rsa.PublicKey
	PGPubK       *rsa.PublicKey
}

func GenerateCryptoParams(context *SessionContext) {
	context.RsaKey, _ = rsa.GenerateKey(rand.Reader, context.config.RsaBits)
	context.PGPubK = context.config.PGPubK
}

func GetWebSegment(context *SessionContext) {
	err := context.Decoder.Decode(&context.WebSegment)
	if err != nil {
		panic(err)
	}

	fmt.Printf("0. Connected to merchant: %s\n", context.WebSegment.MerchantInfo.Name)
	verification, err := signature.Verify(context.WebSegment.Signature, context.PGPubK, &context.WebSegment.MerchantInfo)
	if !verification {
		panic("0. Merchant info signature doesn't verify")
	} else {
		fmt.Println("0. Merchant signature verified")
	}
	context.MerchantPubK = context.WebSegment.MerchantInfo.MerchantPubKey
}

func SendPublicKey(context *SessionContext) {
	fmt.Println("1. Sending encrypted public key to merchant")
	err := hybrid_encryption.EncryptToStream(&context.RsaKey.PublicKey, context.WebSegment.MerchantInfo.MerchantPubKey, context.Encoder)
	if err != nil {
		panic(err)
	}
}

func GetTransactionSid(context *SessionContext) {
	var sidData protocol.MerchantSid
	err := hybrid_encryption.DecryptFromStream(&sidData, context.RsaKey, context.Decoder)
	if err != nil {
		panic(err)
	}
	verification, err := signature.Verify(sidData.SidSignature, context.MerchantPubK, &sidData.Sid)
	if err != nil {
		panic(err)
	}
	if !verification {
		panic("2. Sid not verified")
	} else {
		fmt.Println("2. Merchant SID signature verified")
	}
	fmt.Printf("2. Merchant generated SID: %v\n", sidData.Sid)
	context.SessionID = sidData.Sid
}

func SendTransactionInfo(context *SessionContext) {
	amount := 1.0

	paymentInfo := protocol.PaymentInfo{
		Sid:     context.SessionID,
		Amount:  amount,
		CardExp: "07/10",
		CardN:   "123456789ABC",
		CCode:   "123",
		M:       context.WebSegment.MerchantInfo.Name,
		PubKC:   &context.RsaKey.PublicKey}

	context.SessionNonce = make([]byte, 2084)
	_, err := rand.Read(context.SessionNonce)
	paymentInfo.NC = context.SessionNonce

	// Sign payment info
	paymentMessage := protocol.PaymentMessage{
		Info: paymentInfo,
	}
	paymentMessage.DigitalSignature, err = signature.Sign(&paymentInfo, context.RsaKey)
	if err != nil {
		panic(err)
	}

	paymentOrder := protocol.PaymentOrder{
		PaymentOrder: protocol.PaymentOrderSignedFields{
			Amount:    amount,
			Sid:       context.SessionID,
			OrderDesc: "My blue submarine"}}
	paymentOrder.DigitalSignature, err = signature.Sign(&paymentOrder.PaymentOrder, context.RsaKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("3. Sending info for %v\n", paymentOrder.PaymentOrder.OrderDesc)
	paymentToMerchant := protocol.PaymentMessageToMerchant{PO: paymentOrder}
	paymentToMerchant.EncryptedPM, err = hybrid_encryption.Encrypt(&paymentMessage, context.PGPubK)
	err = hybrid_encryption.EncryptToStream(&paymentToMerchant, context.MerchantPubK, context.Encoder)
	if err != nil {
		panic(err)
	}
}

func ReceivePGResponse(context *SessionContext) {
	var pgResponse protocol.PaymentGatewayResponse
	err := hybrid_encryption.DecryptFromStream(&pgResponse, context.RsaKey, context.Decoder)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("6. Got PG Response: %v\n", pgResponse.Resp)
}

func main() {
	fmt.Println("Starting Customer ...")
	var context SessionContext
	context.config.ReadFile("../../config/app_config.json")

	GenerateCryptoParams(&context)

	address := fmt.Sprintf("localhost%s", context.config.MerchantPort)
	conn, err := net.Dial("tcp", address)
	defer conn.Close()

	if err != nil {
		panic(err)
	}
	context.Decoder = json.NewDecoder(conn)
	context.Encoder = json.NewEncoder(conn)

	// 0. Get merchant public key
	GetWebSegment(&context)

	// 1. Send my public key
	SendPublicKey(&context)

	// 2. Get SID
	GetTransactionSid(&context)

	// 3. Send info
	SendTransactionInfo(&context)

	// 6. Receive PG response
	ReceivePGResponse(&context)

}
