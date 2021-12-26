package eap

import(
	// tlsclient "github.com/C0d5/go-tls/core"
	model "github.com/C0d5/go-tls/model"
	"fmt"
)

func TLSHello() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	version := [2]byte{0x03,0x03}
	clientHello := model.MakeClientHello(version)
	clientHelloPayload := clientHello.GetClientHelloPayload()
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer : HeaderEap{
				code : EAPRequest,
				id : 13,
				length:0,
				msgType: TLS,
			},
			Flags : FlagLength,
			Length: uint32(len(clientHelloPayload)),
		},
		Data : clientHelloPayload,
	}
	_,buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}


func TLSClientKeyExchange() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	version := [2]byte{0x03,0x03}
	clientHello := model.MakeClientHello(version)
	clientHelloPayload := clientHello.GetClientHelloPayload()
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer : HeaderEap{
				code : EAPRequest,
				id : 13,
				length:0,
				msgType: TLS,
			},
			Flags : FlagLength,
			Length: uint32(len(clientHelloPayload)),
		},
		Data : clientHelloPayload,
	}
	_,buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}