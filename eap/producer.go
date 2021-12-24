package eap

import(
	// tlsclient "github.com/C0d5/go-tls/core"
	model "github.com/C0d5/go-tls/model"
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
				msgType: TLS,
			},
			Flags : FlagStart,
			Length: uint32(len(clientHelloPayload)),
		},
		Data : clientHelloPayload,
	}
	_,buf := eap.Encode()
	print(buf)
	return buf
}