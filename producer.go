package eap

import(
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	tlsclient "github.com/C0d5/go-tls/core"
	model "github.com/C0d5/go-tls/model"
)

func TLSHello() []byte {
	client := tlsclient.MakeTLSClient()
	clientHello := model.MakeClientHello(client.tlsVersion)
	clientHelloPayload := clientHello.GetClientHelloPayload()
	eap := &TLSPacket{
		PacketHeader: &PacketHeader{
			Outer : &{
				code : EAPRequest,
				id : 13,
				msgType: TLS
			},
			Flags : FlagStart,
			Lengthv: len(clientHelloPayload)
		},
		Data : clientHelloPayload
	}
	_,buf := eap.Encode()
	print(buf)
	return buf
}