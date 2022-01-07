package model

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type ServerHello struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	ServerVersion     [2]byte
	ServerRandom      [32]byte
	SessionIDLength   [1]byte
	SessionID         []byte
	CipherSuite       [2]byte
	CompressionMethod [1]byte
}

func ParseServerHello(answer []byte) (ServerHello, []byte, error) {
	log.Info("Parsing Server Hello")
	offset := 0
	serverHello := ServerHello{}

	serverHello.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	if serverHello.RecordHeader.Type != constants.RecordHandshake {
		return serverHello, answer, helpers.ServerHelloMissingError()
	}

	serverHello.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverHello.HandshakeHeader.MessageType != constants.HandshakeServerHello {
		return serverHello, answer, helpers.ServerHelloMissingError()
	}

	copy(serverHello.ServerVersion[:], answer[offset:offset+2])
	copy(serverHello.ServerRandom[:], answer[offset+2:offset+34])
	copy(serverHello.SessionIDLength[:], answer[offset+34:offset+35])

	sessionIDLenghtInt := int(serverHello.SessionIDLength[0])
	if sessionIDLenghtInt > 0 {
		serverHello.SessionID = answer[offset+35 : offset+sessionIDLenghtInt+35]
		offset += sessionIDLenghtInt
	}

	copy(serverHello.CipherSuite[:], answer[offset+35:offset+37])
	copy(serverHello.CompressionMethod[:], answer[offset+37:offset+38])
	offset += 38

	// if there are unparsed bytes, try to read extension length
	serverHelloLength := int(helpers.ConvertByteArrayToUInt16(serverHello.RecordHeader.Length))
	if serverHelloLength != (offset - 5) { // 5 is the length of RecordHeader
		var extensionLength [2]byte
		copy(extensionLength[:], answer[offset:offset+2])
		offset += 2
		extensionLengthInt := int(helpers.ConvertByteArrayToUInt16(extensionLength))
		offset += extensionLengthInt

	}

	if serverHelloLength != (offset - 5) { // 5 is the length of RecordHeader
		return serverHello, answer, helpers.ServerHelloParsingError()
	}

	return serverHello, answer[offset:], nil
}

func (serverHello ServerHello) SaveJSON() {
	file, _ := os.OpenFile("ServerHello.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverHello)
}

func (serverHello ServerHello) String() string {
	out := fmt.Sprintf("Server Hello\n")
	out += fmt.Sprint(serverHello.RecordHeader)
	out += fmt.Sprint(serverHello.HandshakeHeader)
	out += fmt.Sprintf("  Server Version.....: %6x - %s\n", serverHello.ServerVersion, constants.GTlsVersions.GetVersionForByteCode(serverHello.ServerVersion))
	out += fmt.Sprintf("  Server Random......: %6x\n", serverHello.ServerRandom)
	out += fmt.Sprintf("  Session ID length..: %6x\n", serverHello.SessionIDLength)
	out += fmt.Sprintf("  Session ID.........: %6x\n", serverHello.SessionID)
	out += fmt.Sprintf("  CipherSuite........: %6x - %s\n", serverHello.CipherSuite, constants.GCipherSuites.GetSuiteForByteCode(serverHello.CipherSuite))
	out += fmt.Sprintf("  CompressionMethod..: %6x\n", serverHello.CompressionMethod)
	return out
}

func (serverHello *ServerHello) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader      RecordHeader    `json:"RecordHeader"`
		HandshakeHeader   HandshakeHeader `json:"HandshakeHeader"`
		ServerVersion     string          `json:"SeverVersion"`
		ServerRandom      string          `json:"ServerRandom"`
		SessionID         string          `json:"SessionID"`
		CipherSuite       string          `json:"CipherSuite"`
		CompressionMethod uint8           `json:"CompressionMethod"`
	}{
		RecordHeader:      serverHello.RecordHeader,
		HandshakeHeader:   serverHello.HandshakeHeader,
		ServerVersion:     constants.GTlsVersions.GetVersionForByteCode(serverHello.ServerVersion),
		ServerRandom:      hex.EncodeToString(serverHello.ServerRandom[:]),
		SessionID:         hex.EncodeToString(serverHello.SessionID),
		CipherSuite:       constants.GCipherSuites.GetSuiteForByteCode(serverHello.CipherSuite),
		CompressionMethod: serverHello.CompressionMethod[0],
	})
}
