package config

import (
	"bufio"
	"crypto/rsa"
	"encoding/json"
	"os"
)

type AppConfig struct {
	MerchantPort          string         `json:"merchant_port"`
	PaymentGatewayTcp     string         `json:"payment_gateway_tcp"`
	PaymentGatewaySignTcp string         `json:"payment_gateway_sign_tcp"`
	RsaBits               int            `json:"rsa_bits"`
	PGPubK                *rsa.PublicKey `json:"payment_gateway_pk"`
}

func (a *AppConfig) ReadFile(path string) {
	configFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(configFile)
	decoder := json.NewDecoder(reader)
	err = decoder.Decode(a)
	if err != nil {
		panic(err)
	}
}

func (a *AppConfig) WriteToFile(path string) {
	configFile, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	decoder := json.NewEncoder(configFile)
	err = decoder.Encode(a)
	if err != nil {
		panic(err)
	}
	configFile.Close()

}
