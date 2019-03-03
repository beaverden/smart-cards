package http_api

import (
	"encoding/json"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"net/http"
)

func signApiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid header"))
		return
	}

	var message struct {
		Data []byte `json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&message)
	defer r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid json; " + err.Error()))
		return
	}
	fmt.Printf("Signing message: %v\n", string(message.Data))

	messageSignature, err := signature.Sign(message.Data, ServerContext.PGPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to sign message"))
		return
	}

	signedData := signature.SignedData{Data: message.Data, Signature: messageSignature}
	responseBytes, err := json.Marshal(signedData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to marshal data"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}
