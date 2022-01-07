package model

import (
	"encoding/json"
	"fmt"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type ServerHelloDone struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
}

func ParseServerHelloDone(answer []byte) (ServerHelloDone, []byte, error) {
	var offset uint32
	offset = 0
	serverHelloDone := ServerHelloDone{}
	serverHelloDone.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	if serverHelloDone.RecordHeader.Type != constants.RecordHandshake {
		return serverHelloDone, answer, helpers.ServerHelloDoneMissingError()
	}

	serverHelloDone.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverHelloDone.HandshakeHeader.MessageType != constants.HandshakeServerHelloDone {
		return serverHelloDone, answer, helpers.ServerHelloDoneMissingError()
	}

	return serverHelloDone, answer[offset:], nil
}

func (serverHelloDone ServerHelloDone) SaveJSON() {
	file, _ := os.OpenFile("ServerHelloDone.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverHelloDone)
}

func (serverHelloDone ServerHelloDone) String() string {
	out := fmt.Sprintf("Server Hello Done\n")
	out += fmt.Sprint(serverHelloDone.RecordHeader)
	out += fmt.Sprint(serverHelloDone.HandshakeHeader)
	return out
}

func (serverHelloDone *ServerHelloDone) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
	}{
		RecordHeader:    serverHelloDone.RecordHeader,
		HandshakeHeader: serverHelloDone.HandshakeHeader,
	})
}
