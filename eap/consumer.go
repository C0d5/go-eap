package eap

// import (
// 	"crypto/rsa"
// 	"fmt"
// 	log "github.com/sirupsen/logrus"
// 	"github.com/C0d5/go-tls/constants"
// 	"github.com/C0d5/go-tls/helpers"
// 	"github.com/C0d5/go-tls/model"
// )

// func (client *TLSClient) ReadFromServer(buff []byte) ([]byte,[]byte) {
// 	log.Info("Reading response")

// 	recordHeader := model.ParseRecordHeader(buff[:5])
// 	recordLen := int(helpers.ConvertByteArrayToUInt16(recordHeader.Length))

// 	record := buff[5:5+recordLen]

// 	log.Debug("Message received from server: %x\n", record)
// 	return record,buff[5+recordLen:]
// }

// func (client *TLSClient) ParseServerHello(record []byte) {

// 	answer,record := client.ReadFromServer(record)
// 	serverHello, _, err := model.ParseServerHello(answer)
// 	if err != nil {
// 		log.Warn(err)
// 	}
// 	client.cipherSuite = *constants.GCipherSuites.GetSuiteInfoForByteCode(serverHello.CipherSuite)
// 	client.securityParams.ServerRandom = serverHello.ServerRandom
// 	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
// 	fmt.Println(serverHello)

// 	answer,record = client.ReadFromServer(record)
// 	serverCertificate, _, err := model.ParseServerCertificate(answer)
// 	if err != nil {
// 		log.Warn(err)
// 	}
// 	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
// 	fmt.Println(serverCertificate)

// 	answer,record = client.ReadFromServer(record)
// 	serverKeyExchange, _, err := model.ParseServerKeyExchange(answer)
// 	if err != nil {
// 		log.Warn(err)
// 	} else {
// 		client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
// 		fmt.Println(serverKeyExchange)
// 	}
// 	client.securityParams.ServerKeyExchangePublicKey = serverKeyExchange.PublicKey
// 	client.securityParams.Curve = constants.GCurves.GetCurveInfoForByteCode(serverKeyExchange.CurveID).Curve

// 	if !serverKeyExchange.VerifySignature(&client.securityParams, serverCertificate.Certificates[0].Certificate.PublicKey.(*rsa.PublicKey)) {
// 		log.Error("Could not verify signature!")
// 	}

// 	answer,record = client.ReadFromServer(record)
// 	serverHelloDone, _, err := model.ParseServerHelloDone(answer)
// 	if err != nil {
// 		log.Warn(err)
// 	}
// 	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
// 	fmt.Println(serverHelloDone)
// }

// func (client *TLSClient) ParseServerHandshake(record []byte) {
// 	answer,record := client.ReadFromServer(record)
// 	serverChangeCipherSpec, _, err := model.ParseServerChangeCipherSpec(answer)
// 	if err != nil {
// 		log.Warn(err)
// 	}

// 	fmt.Println(serverChangeCipherSpec)
// 	answer,record = client.ReadFromServer(record)
// 	serverHandshakeFinished, _, err := model.ParseServerHandshakeFinished(client.securityParams.ServerKey, client.securityParams.ServerIV, answer, 0)
// 	if err != nil {
// 		log.Warn(err)
// 	}
// 	client.serverSeqNumber += 1

// 	fmt.Println(serverHandshakeFinished)
// }
