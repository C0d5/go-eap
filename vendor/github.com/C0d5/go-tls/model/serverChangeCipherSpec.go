package model

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type ServerChangeCipherSpec struct {
	RecordHeader RecordHeader
	Payload      byte
}

func ParseServerChangeCipherSpec(answer []byte) (ServerChangeCipherSpec, []byte, error) {
	var offset uint32
	offset = 0
	serverChangeCipherSpec := ServerChangeCipherSpec{}
	serverChangeCipherSpec.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	if serverChangeCipherSpec.RecordHeader.Type != constants.RecordChangeCipherSpec {
		log.Error("RecordType mismatch")
		return serverChangeCipherSpec, answer, helpers.ServerChangeCipherSpecMissingError()
	}

	serverChangeCipherSpec.Payload = answer[offset]
	offset += 1

	return serverChangeCipherSpec, answer, nil
}

func (serverChangeCipherSpec ServerChangeCipherSpec) SaveJSON() {
	file, _ := os.OpenFile("ServerChangeCipherSpec.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverChangeCipherSpec)
}

func (serverChangeCipherSpec ServerChangeCipherSpec) String() string {
	out := fmt.Sprintf("Server Change Cipher Spec\n")
	out += fmt.Sprint(serverChangeCipherSpec.RecordHeader)
	out += fmt.Sprintf("  Payload.........: %6x\n", serverChangeCipherSpec.Payload)
	return out
}

func (serverChangeCipherSpec *ServerChangeCipherSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader RecordHeader `json:"RecordHeader"`
		Payload      byte         `json:"Payload"`
	}{
		RecordHeader: serverChangeCipherSpec.RecordHeader,
		Payload:      serverChangeCipherSpec.Payload,
	})
}
