package signature

import (
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"github.com/pkg/errors"
)

type RSASignature struct {
	Signature []byte
}

type SignedData struct {
	Data      []byte
	Signature *RSASignature
}

// Signs any data that can be marshaled with json
// If the data parameter is already []byte, it won't be marshaled
// Signs with the hash of the resulting []byte array
// Returns a pointer to a signature
func Sign(data interface{}, key *rsa.PrivateKey) (*RSASignature, error) {
	var jsonData []byte
	switch data.(type) {
	default:
		var err error
		jsonData, err = json.Marshal(data)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case []byte:
		jsonData = data.([]byte)
	}

	dataChecksum := sha256.Sum256(jsonData)
	//fmt.Printf("Signing hash: %v\n", dataChecksum[:])
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, dataChecksum[:])
	//r, s, err := dsa.Sign(rand.Reader, key, dataChecksum[:])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var sig RSASignature
	sig.Signature = signature
	return &sig, nil
}

// Verifies a PKCS1v15 RSA signature against any data that can be marshaled with json
// If the data parameter is already []byte, it won't be marshaled
// It will hash the resulting []byte array and verify the signature
func Verify(signature *RSASignature, pubK *rsa.PublicKey, data interface{}) (bool, error) {
	var jsonData []byte
	switch data.(type) {
	default:
		var err error
		jsonData, err = json.Marshal(data)
		if err != nil {
			return false, errors.WithStack(err)
		}
	case []byte:
		jsonData = data.([]byte)
	}

	hash := sha256.Sum256(jsonData)
	err := rsa.VerifyPKCS1v15(pubK, crypto.SHA256, hash[:], signature.Signature)
	if err != nil {
		return false, errors.WithStack(err)
	}
	return true, nil
}

func GenerateDSAKeyPair() (*dsa.PrivateKey, error) {
	params := new(dsa.Parameters)

	// see http://golang.org/pkg/crypto/dsa/#ParameterSizes
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, errors.WithStack(err)
	}

	privateKey := new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = *params
	err := dsa.GenerateKey(privateKey, rand.Reader) // this generates a public & private key pair
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return privateKey, nil
}
