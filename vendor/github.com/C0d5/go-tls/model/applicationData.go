package model

import (
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/coreUtils"
	"github.com/C0d5/go-tls/cryptoHelpers"
	"github.com/C0d5/go-tls/helpers"
)

type ApplicationData struct {
	RecordHeader RecordHeader
	Data         []byte
	Payload      []byte
}

func MakeApplicationData(clientKey, clientIV, data []byte, tlsVersion [2]byte, seqNum byte) (ApplicationData, error) {
	clientApplicationData := ApplicationData{}
	clientApplicationData.Data = data

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordApplicationData
	recordHeader.ProtocolVersion = tlsVersion
	clientApplicationData.RecordHeader = recordHeader

	additionalData := coreUtils.MakeAdditionalData(seqNum, constants.RecordApplicationData, tlsVersion)
	encryptedContent, err := cryptoHelpers.Encrypt(clientKey, clientIV, data, additionalData)
	if err != nil {
		return clientApplicationData, err
	}

	clientApplicationData.Payload = encryptedContent

	clientApplicationData.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(len(clientApplicationData.Payload)))

	return clientApplicationData, nil
}

func (applicationData ApplicationData) GetPayload() []byte {
	var payload []byte

	payload = append(payload, applicationData.RecordHeader.Type)
	payload = append(payload, applicationData.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, applicationData.RecordHeader.Length[:]...)
	payload = append(payload, applicationData.Payload...)

	return payload
}

func ParseApplicationData(serverKey, serverIV, answer []byte, seqNum byte) (ApplicationData, error) {
	offset := 0
	serverApplicationData := ApplicationData{}

	serverApplicationData.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	if serverApplicationData.RecordHeader.Type != constants.RecordApplicationData {
		return serverApplicationData, helpers.ApplicationDataMissingError()
	}

	serverApplicationData.Payload = answer[offset:]

	additionalData := coreUtils.MakeAdditionalData(seqNum, serverApplicationData.RecordHeader.Type, serverApplicationData.RecordHeader.ProtocolVersion)
	plaintext, err := cryptoHelpers.Decrypt(serverKey, serverIV, serverApplicationData.Payload, additionalData)
	if err != nil {
		return serverApplicationData, err
	}

	serverApplicationData.Data = plaintext

	return serverApplicationData, nil
}
