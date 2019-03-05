package protocol

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"github.com/pkg/errors"
)

type jsonMerchantData struct {
	Name           string
	MerchantPubKey rsa.PublicKey
}

type jsonWebSegment struct {
	MerchantInfo MerchantData
	Signature    *signature.DSASignature
}

func (m *MerchantData) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonMerchantData{Name: m.Name, MerchantPubKey: *m.MerchantPubKey})
}

func (m *MerchantData) UnmarshalJSON(b []byte) error {
	var unmarshalStruct jsonMerchantData
	err := json.Unmarshal(b, &unmarshalStruct)
	if err != nil {
		return errors.WithStack(err)
	}
	m.Name = unmarshalStruct.Name
	m.MerchantPubKey = &unmarshalStruct.MerchantPubKey
	return nil
}

func (w *WebSegment) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonWebSegment{MerchantInfo: w.MerchantInfo, Signature: w.Signature})
}

func (w *WebSegment) UnmarshalJSON(b []byte) error {
	var unmarshalStruct jsonWebSegment
	err := json.Unmarshal(b, &unmarshalStruct)
	if err != nil {
		return errors.WithStack(err)
	}
	w.Signature = unmarshalStruct.Signature
	w.MerchantInfo = unmarshalStruct.MerchantInfo
	return nil
}
