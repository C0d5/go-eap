package main

import (
	"context"
	"log"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"go-eap/eap"
)

func main() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, "tim")
	rfc2865.UserPassword_SetString(packet, "12345")
	rfc2865.EAPMessage_Set(packet,TLSHello())
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}