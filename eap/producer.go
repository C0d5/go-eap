package eap

import(
	// tlsclient "github.com/C0d5/go-tls/core"
	model "github.com/C0d5/go-tls/model"
	cryptoHelpers "github.com/C0d5/go-tls/cryptoHelpers"
	helpers "github.com/C0d5/go-tls/helpers"
	log "github.com/sirupsen/logrus"
	"fmt"
	// "crypto/sha256"
)

func (client *TLSClient) SendTLSHello() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	clientHello := model.MakeClientHello(client.tlsVersion)
	client.securityParams.ClientRandom = clientHello.ClientRandom
	clientHelloPayload := clientHello.GetClientHelloPayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientHelloPayload)...)
	fmt.Println(clientHello)
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer : HeaderEap{
				code : EAPRequest,
				id : client.clientSeqNumber,
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


func (client *TLSClient) SendTLSClientKeyExchange() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	// key := []byte{0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10}
	// version := [2]byte{0x03,0x03}
	// clientKeyExchange, err := model.MakeClientKeyExchangeWithKeys(version, key,key)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// message := make([]byte,0)
	// message = append(message,helpers.IgnoreRecordHeader(clientKeyExchange.GetClientKeyExchangePayload())...)
	// clientChangeCipherSpec := model.MakeClientChangeCipherSpec(version)
	// data := cryptoHelpers.HashByteArray(sha256.New, message)
	// // securityParams := &coreUtils.SecurityParams{}
	// verifyData := cryptoHelpers.MakeVerifyDataUsingKeys(key,key,key,data)
	// if verifyData == nil {
	// 	fmt.Println("Could not create VerifyData")
	// }
	// clientHandshakeFinished, err := model.MakeClientHandshakeFinished(key, key, verifyData, version, 2)
	// finalPayload := append(clientKeyExchange.GetClientKeyExchangePayload(), clientChangeCipherSpec.GetClientChangeCipherSpecPayload()...)
	// finalPayload = append(finalPayload, clientHandshakeFinished.GetClientHandshakeFinishedPayload()...)

	clientKeyExchange, err := model.MakeClientKeyExchange(client.tlsVersion, client.securityParams.Curve)
	if err != nil {
		log.Error(err)
	}
	client.securityParams.ClientKeyExchangePrivateKey = clientKeyExchange.PrivateKey
	clientKeyExchangePayload := clientKeyExchange.GetClientKeyExchangePayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientKeyExchangePayload)...)
	fmt.Println(clientKeyExchange)
	
	clientChangeCipherSpec := model.MakeClientChangeCipherSpec(client.tlsVersion)
	//clientChangeCipherSpec is not a handshake message, so it is not included in the hash input

	// TODO maybe move this to MakeClientHandshakeFinished
	data := cryptoHelpers.HashByteArray(client.cipherSuite.HashingAlgorithm, client.messages)
	verifyData := cryptoHelpers.MakeVerifyData(&client.securityParams, data)
	if verifyData == nil {
		log.Error("Could not create VerifyData")
	}

	clientHandshakeFinished, err := model.MakeClientHandshakeFinished(client.securityParams.ClientKey, client.securityParams.ClientIV, verifyData, client.tlsVersion, client.clientSeqNumber)
	if err != nil {
		log.Error(err)
	}
	client.clientSeqNumber += 1
	fmt.Println(clientHandshakeFinished)
	
	// Send ClientKeyExchange, ClientChangeCipherSpec, ClientHandshakeFinished on the same tcp connection
	finalPayload := append(clientKeyExchangePayload, clientChangeCipherSpec.GetClientChangeCipherSpecPayload()...)
	finalPayload = append(finalPayload, clientHandshakeFinished.GetClientHandshakeFinishedPayload()...)

	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer : HeaderEap{
				code : EAPRequest,
				id : client.clientSeqNumber,
				msgType: TLS,
			},
			Flags : FlagLength,
			Length: uint32(len(finalPayload)),
		},
		Data : finalPayload,
	}
	_,buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}

func (client *TLSClient) SendTLSEmpty() []byte {
	// client := tlsclient.MakeTLSClient("localhost","TLS 1.2",false)
	client.clientSeqNumber += 1
	fmt.Println("Empty Response")
	eap := &TLSPacket{
		PacketHeader: PacketHeader{
			Outer : HeaderEap{
				code : EAPResponse,
				id : client.clientSeqNumber,
				msgType: TLS,
			},
			Flags : FlagLength,
		},
	}
	_,buf := eap.Encode()
	fmt.Println("buffer is :", buf)
	return buf
}