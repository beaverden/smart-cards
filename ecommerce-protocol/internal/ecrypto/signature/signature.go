package signature

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"github.com/pkg/errors"
	"math/big"
)

type DSASignature struct {
	Hash   []byte
	R      *big.Int
	S      *big.Int
	PubKey dsa.PublicKey
}

type SignedData struct {
	Data      []byte
	Signature *DSASignature
}

func Sign(data interface{}, key *dsa.PrivateKey) (*DSASignature, error) {
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
	r, s, err := dsa.Sign(rand.Reader, key, dataChecksum[:])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var sig DSASignature
	sig.R = r
	sig.S = s
	sig.PubKey = key.PublicKey
	sig.Hash = dataChecksum[:]
	return &sig, nil
}

func Verify(signature *DSASignature, data interface{}) (bool, error) {
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
	//fmt.Printf("Verifiyng hash: %v\n", hash[:])
	status := dsa.Verify(&signature.PubKey, hash[:], signature.R, signature.S)
	return status, nil
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
