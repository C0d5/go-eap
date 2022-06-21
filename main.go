package main

import (
	"context"
	"log"

	"github.com/C0d5/go-eap/eap"
	"github.com/C0d5/go-tls/tls"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func main() {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	c := eap.GetTLSClient(conf)
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, "tim")
	rfc2865.UserPassword_SetString(packet, "12345")
	rfc2869.EAPMessage_Set(packet, c.MakeEapIdentity(12, "test001"))
	response, err := radius.Exchange(context.Background(), packet, "8.8.8.8:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}
