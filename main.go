package main

import (
	"context"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"github.com/C0d5/go-eap/eap"
)

func main() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, "tim")
	rfc2865.UserPassword_SetString(packet, "12345")
	rfc2869.EAPMessage_Set(packet,eap.TLSClientKeyExchange())
	response, err := radius.Exchange(context.Background(), packet, "8.8.8.8:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}