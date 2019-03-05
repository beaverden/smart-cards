package http_api

import (
	"encoding/json"
	"fmt"
	"github.com/beaverden/smart-cards/ecommerce-protocol/internal/ecrypto/signature"
	"io/ioutil"
	"net/http"
)

func signApiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid header"))
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to read request body"))
	}

	messageSignature, err := signature.Sign(body, ServerContext.PGPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to sign message"))
		return
	}

	responseBytes, err := json.Marshal(&messageSignature)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Unable to marshal data"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
	fmt.Println(string(responseBytes))
}
