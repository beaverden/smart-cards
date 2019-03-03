package main

import (
	"encoding/json"
	"fmt"
	ecryptoSignature "github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"net/http"
	"bytes"
)

func main() {
	fmt.Println("Starting Merchant ...")

	var message struct {
		Data []byte `json:"data"`
	}
	message.Data = []byte("hello!")
	encoded, _ := json.Marshal(message)

	resp, _ := http.Post("http://localhost:12345/signSegment", "application/json", bytes.NewReader(encoded))
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()

	var signedData ecryptoSignature.SignedData
	err := decoder.Decode(&signedData)
	if err != nil {
		panic(err)
	}
	verified, _ := ecryptoSignature.Verify(signedData.Signature)
	fmt.Println(verified)
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
