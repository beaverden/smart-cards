package config

type PortConfig struct {
	MerchantPort       string `json:"merchant_port"`
	PaymentGatewayTcp  string `json:"payment_gateway_tcp"`
	PaymentGatewayHttp string `json:"payment_gateway_http"`
}
