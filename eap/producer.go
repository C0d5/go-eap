package eap

import (
	"crypto/tls"
	"fmt"
	"log"
)

func (client *TLSClient) MakeEapIdentity(id uint8, identity string) []byte {
	eap := &EapPacket{
		code: EAPResponse, id: id, length: 0, msgType: Identity,
		Payload: &EapIdentity{
			identity: identity,
		},
	}
	_, buf := eap.Encode()
	// fmt.Println("buffer is :", buf)
	return buf
}

func (client *TLSClient) MakeTLSHello(id uint8) []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	clientHello, _, err := client.Conn.MakeClientHello()
	if err != nil {
		log.Println(err)
		return nil
	}
	return clientHello.Marshal()
}

func (client *TLSClient) SendTLSHello(id uint8) []byte {

	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	clientHello, _, err := client.Conn.MakeClientHello()
	if err != nil {
		log.Println(err)
	}
	client.Hello = clientHello
	client.Session = client.Conn.GetSession(clientHello)
	clientHelloPayload := clientHello.Marshal()
	m := len(clientHelloPayload)
	outBuf := make([]byte, 5)
	outBuf[0] = byte(22)
	vers := tls.VersionTLS10
	outBuf[1] = byte(vers >> 8)
	outBuf[2] = byte(vers)
	outBuf[3] = byte(m >> 8)
	outBuf[4] = byte(m)
	// fmt.Println("Client Hello Payload.", clientHello)
	outBuf = append(outBuf, clientHelloPayload...)
	eap := &EapPacket{
		code: EAPResponse, id: id, length: 0, msgType: TLS,
		Payload: &TLSPacket{
			PacketHeader: PacketHeader{
				Flags:  FlagLength,
				Length: uint32(m + 5),
			},
			Data: outBuf,
		},
	}
	_, buf := eap.Encode()
	// fmt.Println("buffer is :", buf)
	return buf
}

func (client *TLSClient) SendTLSEmpty() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	fmt.Println("Empty Response")
	eap := &EapPacket{
		code: EAPResponse, id: 10, msgType: TLS,
		Payload: &TLSPacket{
			PacketHeader: PacketHeader{
				Flags: FlagLength,
			},
		},
	}
	_, buf := eap.Encode()
	// fmt.Println("buffer is :", buf)
	return buf
}

func (client *TLSClient) SendClientCertificate(id uint8, l int) ([]byte, bool) {
	moreFragment := false
	ckx := client.Conn.GetSendBuf()
	flag := FlagNone
	m := len(ckx)
	if len(ckx) > l {
		client.Buf = ckx[l:]
		ckx = ckx[:l]
		moreFragment = true
		flag = FlagLengthMore
	}
	fmt.Println("sending Client Key Xchange Payload.")
	eap := &EapPacket{
		code: EAPResponse, id: id, msgType: TLS,
		Payload: &TLSPacket{
			PacketHeader: PacketHeader{
				Flags:  flag,
				Length: uint32(m),
			},
			Data: ckx,
		},
	}
	_, buf := eap.Encode()
	// fmt.Println("buffer is :", buf)
	return buf, moreFragment
}

func (client *TLSClient) SendPendingBuffer(id uint8, l int) ([]byte, bool) {
	moreFragment := false
	var ckx []byte
	flag := FlagNone
	if len(client.Buf) > l {
		ckx = ckx[:l]
		client.Buf = client.Buf[l:]
		moreFragment = true
		flag = FlagMore
	} else {
		ckx = client.Buf
		client.Buf = []byte{}
	}
	m := len(ckx)
	fmt.Println("sending More Client Key Xchange Payload.")
	eap := &EapPacket{
		code: EAPResponse, id: id, msgType: TLS,
		Payload: &TLSPacket{
			PacketHeader: PacketHeader{
				Flags:  flag,
				Length: uint32(m),
			},
			Data: ckx,
		},
	}
	_, buf := eap.Encode()
	// fmt.Println("buffer is :", buf)
	return buf, moreFragment
}
