package signature

import (
	"crypto/dsa"
	"encoding/json"
	"github.com/pkg/errors"
	"math/big"
)

type jsonDSASignature struct {
	Hash   []byte        `json:"hash"`
	R      string        `json:"r"`
	S      string        `json:"s"`
	PubKey dsa.PublicKey `json:"pubKey"`
}

type jsonSignedData struct {
	Data      []byte       `json:"data"`
	Signature DSASignature `json:"signature"`
}

func (d *DSASignature) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonDSASignature{d.Hash, d.R.String(), d.S.String(), d.PubKey})
}

func (d *DSASignature) UnmarshalJSON(b []byte) error {
	var unmarshalStruct jsonDSASignature
	err := json.Unmarshal(b, &unmarshalStruct)
	if err != nil {
		return errors.WithStack(err)
	}
	var R big.Int
	var S big.Int
	R.SetString(unmarshalStruct.R, 10)
	S.SetString(unmarshalStruct.S, 10)
	d.Hash = unmarshalStruct.Hash
	d.R = &R
	d.S = &S
	d.PubKey = unmarshalStruct.PubKey
	return nil
}

func (d *SignedData) MarshalJSON() ([]byte, error) {

	return json.Marshal(jsonSignedData{d.Data, *d.Signature})
}

func (d *SignedData) UnmarshalJSON(b []byte) error {
	var unmarshalStruct jsonSignedData
	err := json.Unmarshal(b, &unmarshalStruct)
	if err != nil {
		return errors.WithStack(err)
	}
	d.Data = unmarshalStruct.Data
	d.Signature = &unmarshalStruct.Signature
	return nil
}
