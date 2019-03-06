package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	config2 "github.com/beaverden/smart-cards/ecommerce-protocol/config"
	"os"
)

func Generate() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	pemPrivateFile, err := os.Create("../../../config/private/pg_private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemPrivateFile.Close()

	var config config2.AppConfig
	config.ReadFile("../../../config/app_config.json")
	config.PGPubK = &rsaKey.PublicKey
	config.WriteToFile("../../../config/app_config.json")
}
