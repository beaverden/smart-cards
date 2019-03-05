package main

import (
	"encoding/json"
	"fmt"
	config2 "github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/protocol"
	"github.com/tkanos/gonfig"
	"net"
)

func main() {
	fmt.Println("Starting Merchant ...")
	var config config2.PortConfig
	err := gonfig.GetConf("../../config/app_ports.json", &config)
	if err != nil {
		panic(err)
	}

	//key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	address := fmt.Sprintf("localhost%s", config.MerchantPort)
	conn, err := net.Dial("tcp", address)
	defer conn.Close()

	if err != nil {
		panic(err)
	}
	//data := make([]byte, 5000)
	//_, err = conn.Read(data)
	//fmt.Println(string(data))
	//encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	var segment protocol.WebSegment
	err = decoder.Decode(&segment)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to merchant: %s\n", segment.MerchantInfo.Name)
	verification, err := signature.Verify(segment.Signature, &segment.MerchantInfo)
	if !verification {
		panic("Merchant info signature doesn't verify")
	}

}
