package http_api

import (
	"crypto/dsa"
	"net/http"
)

type HTTPApiContext struct {
	PrivateKey *dsa.PrivateKey
}
var HttpContext *HTTPApiContext


func StartHTTPApiHandler(ctx *HTTPApiContext) {
	HttpContext = ctx
	http.HandleFunc("/signSegment", signApiHandler)
	http.ListenAndServe(":12345", nil)
}
