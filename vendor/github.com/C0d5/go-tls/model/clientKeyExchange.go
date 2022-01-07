package model

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type ClientKeyExchange struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	PublicKeyLength byte
	PublicKey       []byte
	PrivateKey      []byte
}

func MakeClientKeyExchange(tlsVersion [2]byte, curve elliptic.Curve) (ClientKeyExchange, error) {
	clientKeyExchange := ClientKeyExchange{}

	privateKey, privateKeyX, privateKeyY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Error("Failed to generate private key")
		return clientKeyExchange, err
	}

	publicKey := elliptic.Marshal(curve, privateKeyX, privateKeyY)

	clientKeyExchange.PublicKeyLength = byte(len(publicKey))
	clientKeyExchange.PublicKey = publicKey

	clientKeyExchange.PrivateKey = privateKey

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = tlsVersion

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientKeyExchange
	handshakeHeader.MessageLength = clientKeyExchange.getHandshakeHeaderLength()
	clientKeyExchange.HandshakeHeader = handshakeHeader

	recordHeader.Length = clientKeyExchange.getRecordLength()
	clientKeyExchange.RecordHeader = recordHeader

	return clientKeyExchange, nil
}

func MakeClientKeyExchangeWithKeys(tlsVersion [2]byte, publicKey,privateKey [] byte) (ClientKeyExchange, error) {
	clientKeyExchange := ClientKeyExchange{}

	clientKeyExchange.PublicKeyLength = byte(len(publicKey))
	clientKeyExchange.PublicKey = publicKey

	clientKeyExchange.PrivateKey = privateKey

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = tlsVersion

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientKeyExchange
	handshakeHeader.MessageLength = clientKeyExchange.getHandshakeHeaderLength()
	clientKeyExchange.HandshakeHeader = handshakeHeader

	recordHeader.Length = clientKeyExchange.getRecordLength()
	clientKeyExchange.RecordHeader = recordHeader

	return clientKeyExchange, nil
}

func (clientKeyExchange ClientKeyExchange) getHandshakeHeaderLength() [3]byte {
	var length [3]byte

	k := uint16(clientKeyExchange.PublicKeyLength)
	k += 1 // size of PublicKeyLength

	tmp := helpers.ConvertIntToByteArray(k)
	length[0] = 0x00
	length[1] = tmp[0]
	length[2] = tmp[1]

	return length
}

func (clientKeyExchange ClientKeyExchange) getRecordLength() [2]byte {
	tmp := int(helpers.Convert3ByteArrayToUInt32(clientKeyExchange.HandshakeHeader.MessageLength))
	tmp += 1 // size of MessageType
	tmp += len(clientKeyExchange.HandshakeHeader.MessageLength)

	return helpers.ConvertIntToByteArray(uint16(tmp))
}

func (clientKeyExchange ClientKeyExchange) GetClientKeyExchangePayload() []byte {
	var payload []byte

	payload = append(payload, clientKeyExchange.RecordHeader.Type)
	payload = append(payload, clientKeyExchange.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientKeyExchange.RecordHeader.Length[:]...)
	payload = append(payload, clientKeyExchange.HandshakeHeader.MessageType)
	payload = append(payload, clientKeyExchange.HandshakeHeader.MessageLength[:]...)
	payload = append(payload, clientKeyExchange.PublicKeyLength)
	payload = append(payload, clientKeyExchange.PublicKey...)

	return payload
}

func (clientKeyExchange ClientKeyExchange) SaveJSON() {
	file, _ := os.OpenFile("ClientKeyExchange.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&clientKeyExchange)
}

func (clientKeyExchange ClientKeyExchange) String() string {
	out := fmt.Sprintf("Client Key Exchange\n")
	out += fmt.Sprint(clientKeyExchange.RecordHeader)
	out += fmt.Sprint(clientKeyExchange.HandshakeHeader)
	out += fmt.Sprintf("  PublicKeyLength.....: %6x\n", clientKeyExchange.PublicKeyLength)
	out += fmt.Sprintf("  PublicKey.....: %6x\n", clientKeyExchange.PublicKey)
	out += fmt.Sprintf("  PrivateKey....: %6x\n", clientKeyExchange.PrivateKey)
	return out
}

func (clientKeyExchange *ClientKeyExchange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
		PublicKey       string          `json:"PublicKey"`
		PrivateKey      string          `json:"PrivateKey"`
	}{
		RecordHeader:    clientKeyExchange.RecordHeader,
		HandshakeHeader: clientKeyExchange.HandshakeHeader,
		PublicKey:       hex.EncodeToString(clientKeyExchange.PublicKey),
		PrivateKey:      hex.EncodeToString(clientKeyExchange.PrivateKey),
	})
}
