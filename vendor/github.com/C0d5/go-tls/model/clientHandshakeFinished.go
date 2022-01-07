package model

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/coreUtils"
	"github.com/C0d5/go-tls/cryptoHelpers"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

const (
	verifyDataLength = 12
)

type ClientHandshakeFinished struct {
	RecordHeader     RecordHeader
	HandshakeHeader  HandshakeHeader
	VerifyData       []byte
	EncryptedContent []byte
}

func MakeClientHandshakeFinished(clientKey, clientIV, verifyData []byte, tlsVersion [2]byte, seqNum byte) (ClientHandshakeFinished, error) {
	clientHandshakeFinished := ClientHandshakeFinished{}

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = tlsVersion
	clientHandshakeFinished.RecordHeader = recordHeader

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientFinished
	handshakeHeader.MessageLength = helpers.ConvertIntTo3ByteArray(verifyDataLength)
	clientHandshakeFinished.HandshakeHeader = handshakeHeader

	clientHandshakeFinished.VerifyData = verifyData

	var plaintext []byte
	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageType)
	plaintext = append(plaintext, clientHandshakeFinished.HandshakeHeader.MessageLength[:]...)
	plaintext = append(plaintext, clientHandshakeFinished.VerifyData...)

	additionalData := coreUtils.MakeAdditionalData(seqNum, clientHandshakeFinished.RecordHeader.Type, tlsVersion)
	encryptedContent, err := cryptoHelpers.Encrypt(clientKey, clientIV, plaintext, additionalData)
	if err != nil {
		return clientHandshakeFinished, err
	}
	clientHandshakeFinished.EncryptedContent = encryptedContent

	clientHandshakeFinished.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(encryptedContent)))

	return clientHandshakeFinished, nil
}

func (clientHandshakeFinished ClientHandshakeFinished) GetClientHandshakeFinishedPayload() []byte {
	var payload []byte

	payload = append(payload, clientHandshakeFinished.RecordHeader.Type)
	payload = append(payload, clientHandshakeFinished.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHandshakeFinished.RecordHeader.Length[:]...)
	payload = append(payload, clientHandshakeFinished.EncryptedContent...)

	return payload
}

func (clientHandshakeFinished ClientHandshakeFinished) SaveJSON() {
	file, _ := os.OpenFile("ClientHandshakeFinished.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&clientHandshakeFinished)
}

func (clientHandshakeFinished ClientHandshakeFinished) String() string {
	out := fmt.Sprintf("Client Handshake Finished\n")
	out += fmt.Sprint(clientHandshakeFinished.RecordHeader)
	out += fmt.Sprint(clientHandshakeFinished.HandshakeHeader)
	out += fmt.Sprintf("  VerifyData.........: %6x\n", clientHandshakeFinished.VerifyData)
	return out
}

func (clientHandshakeFinished *ClientHandshakeFinished) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
		VerifyData      string          `json:"VerifyData"`
	}{
		RecordHeader:    clientHandshakeFinished.RecordHeader,
		HandshakeHeader: clientHandshakeFinished.HandshakeHeader,
		VerifyData:      hex.EncodeToString(clientHandshakeFinished.VerifyData),
	})
}
