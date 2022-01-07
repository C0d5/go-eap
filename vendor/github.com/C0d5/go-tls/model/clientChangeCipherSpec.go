package model

import (
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
)

type ClientChangeCipherSpec struct {
	RecordHeader RecordHeader
	Payload      byte
}

func MakeClientChangeCipherSpec(tlsVersion [2]byte) ClientChangeCipherSpec {
	clientChangeCipherSpec := ClientChangeCipherSpec{}

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordChangeCipherSpec
	recordHeader.ProtocolVersion = tlsVersion
	recordHeader.Length = helpers.ConvertIntToByteArray(uint16(1))

	clientChangeCipherSpec.RecordHeader = recordHeader
	clientChangeCipherSpec.Payload = 0x01

	return clientChangeCipherSpec
}

func (clientChangeCipherSpec ClientChangeCipherSpec) GetClientChangeCipherSpecPayload() []byte {
	var payload []byte

	payload = append(payload, clientChangeCipherSpec.RecordHeader.Type)
	payload = append(payload, clientChangeCipherSpec.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientChangeCipherSpec.RecordHeader.Length[:]...)
	payload = append(payload, clientChangeCipherSpec.Payload)

	return payload
}
