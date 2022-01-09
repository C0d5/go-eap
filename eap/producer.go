package eap

import (
	"crypto/tls"
	"fmt"
	"log"
)

func (client *TLSClient) SendTLSHello() []byte {

	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	clientHello, _, err := client.conn.MakeClientHello()
	if err != nil {
		log.Println(err)
	}
	clientHelloPayload := clientHello.Marshal()
	m := len(clientHelloPayload)
	outBuf := make([]byte, 5)
	outBuf[0] = byte(22)
	vers := tls.VersionTLS10
	outBuf[1] = byte(vers >> 8)
	outBuf[2] = byte(vers)
	outBuf[3] = byte(m >> 8)
	outBuf[4] = byte(m)
	fmt.Println(clientHello)
	outBuf = append(outBuf, clientHelloPayload...)
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer: HeaderEap{
				code:    EAPRequest,
				id:      10,
				length:  0,
				msgType: TLS,
			},
			Flags:  FlagLength,
			Length: uint32(m + 5),
		},
		Data: outBuf,
	}
	_, buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}

// func (client *TLSClient) SendTLSClientKeyExchange() []byte {

// 	clientKeyExchange, err := model.MakeClientKeyExchange(client.tlsVersion, client.securityParams.Curve)
// 	if err != nil {
// 		log.Error(err)
// 	}
// 	client.securityParams.ClientKeyExchangePrivateKey = clientKeyExchange.PrivateKey
// 	clientKeyExchangePayload := clientKeyExchange.GetClientKeyExchangePayload()
// 	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientKeyExchangePayload)...)
// 	fmt.Println(clientKeyExchange)

// 	clientChangeCipherSpec := model.MakeClientChangeCipherSpec(client.tlsVersion)
// 	//clientChangeCipherSpec is not a handshake message, so it is not included in the hash input

// 	// TODO maybe move this to MakeClientHandshakeFinished
// 	data := cryptoHelpers.HashByteArray(client.cipherSuite.HashingAlgorithm, client.messages)
// 	verifyData := cryptoHelpers.MakeVerifyData(&client.securityParams, data)
// 	if verifyData == nil {
// 		log.Error("Could not create VerifyData")
// 	}

// 	clientHandshakeFinished, err := model.MakeClientHandshakeFinished(client.securityParams.ClientKey, client.securityParams.ClientIV, verifyData, client.tlsVersion, client.clientSeqNumber)
// 	if err != nil {
// 		log.Error(err)
// 	}
// 	client.clientSeqNumber += 1
// 	fmt.Println(clientHandshakeFinished)

// 	// Send ClientKeyExchange, ClientChangeCipherSpec, ClientHandshakeFinished on the same tcp connection
// 	finalPayload := append(clientKeyExchangePayload, clientChangeCipherSpec.GetClientChangeCipherSpecPayload()...)
// 	finalPayload = append(finalPayload, clientHandshakeFinished.GetClientHandshakeFinishedPayload()...)

// 	eap := &TLSPacket{
// 		PacketHeader: PacketHeader{
// 			Outer: HeaderEap{
// 				code:    EAPRequest,
// 				id:      client.clientSeqNumber,
// 				msgType: TLS,
// 			},
// 			Flags:  FlagLength,
// 			Length: uint32(len(finalPayload)),
// 		},
// 		Data: finalPayload,
// 	}
// 	_, buf := eap.Encode()
// 	fmt.Println("buffer is :", buf)
// 	return buf
// }

func (client *TLSClient) SendTLSEmpty() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	fmt.Println("Empty Response")
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer: HeaderEap{
				code:    EAPResponse,
				id:      10,
				msgType: TLS,
			},
			Flags: FlagLength,
		},
	}
	_, buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}
