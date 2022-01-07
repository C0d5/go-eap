package model

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/coreUtils"
	"github.com/C0d5/go-tls/cryptoHelpers"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type Signature struct {
	Algorithm [2]byte
	Length    [2]byte
	Content   []byte
}

func ParseSignature(answer []byte) (Signature, []byte) {
	var offset uint32
	offset = 0

	signature := Signature{}

	copy(signature.Algorithm[:], answer[offset:offset+2])
	offset += 2

	copy(signature.Length[:], answer[offset:offset+2])
	offset += 2

	tmpLength := uint32(helpers.ConvertByteArrayToUInt16(signature.Length))
	signature.Content = answer[offset : offset+tmpLength]
	offset += tmpLength

	return signature, answer[offset:]
}

func (signature Signature) String() string {
	out := fmt.Sprintf("Signature\n")
	out += fmt.Sprintf("  Algorithm.....: %6x\n", signature.Algorithm)
	out += fmt.Sprintf("  Length........: %6x\n", signature.Length)
	out += fmt.Sprintf("  Signature.....: %6x\n", signature.Content)
	return out
}

func (signature *Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Algorithm string `json:"SignatureAlgorithm"`
		Length    uint16 `json:"Length"`
		Content   string `json:"SignatureContent"`
	}{
		Algorithm: constants.GSignatureAlgorithms.GetAlgorithmNameForByteCode(signature.Algorithm),
		Length:    helpers.ConvertByteArrayToUInt16(signature.Length),
		Content:   hex.EncodeToString(signature.Content),
	})
}

type ServerKeyExchange struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	Curve           byte
	CurveID         [2]byte
	PublicKeyLength byte
	PublicKey       []byte
	Signature       Signature
}

func ParseServerKeyExchange(answer []byte) (ServerKeyExchange, []byte, error) {
	var offset uint32
	offset = 0
	serverKeyExchange := ServerKeyExchange{}
	serverKeyExchange.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverKeyExchange.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverKeyExchange.HandshakeHeader.MessageType != constants.HandshakeServerKeyExchange {
		return serverKeyExchange, answer, helpers.ServerKeyExchangeMissingError()
	}

	serverKeyExchange.Curve = answer[offset]
	offset += 1

	copy(serverKeyExchange.CurveID[:], answer[offset:offset+2])
	offset += 2

	serverKeyExchange.PublicKeyLength = answer[offset]
	offset += 1

	tmpLength := uint32(serverKeyExchange.PublicKeyLength)
	serverKeyExchange.PublicKey = answer[offset : offset+tmpLength]
	offset += tmpLength

	serverKeyExchange.Signature, answer = ParseSignature(answer[offset:])

	return serverKeyExchange, answer, nil
}

func (serverKeyExchange ServerKeyExchange) VerifySignature(securityParams *coreUtils.SecurityParams, pubKey *rsa.PublicKey) bool {
	var verifySignatureData []byte
	verifySignatureData = append(verifySignatureData, securityParams.ClientRandom[:]...)
	verifySignatureData = append(verifySignatureData, securityParams.ServerRandom[:]...)
	verifySignatureData = append(verifySignatureData, serverKeyExchange.Curve)
	verifySignatureData = append(verifySignatureData, serverKeyExchange.CurveID[:]...)
	verifySignatureData = append(verifySignatureData, serverKeyExchange.PublicKeyLength)
	verifySignatureData = append(verifySignatureData, serverKeyExchange.PublicKey...)

	algorithm := constants.GSignatureAlgorithms.GetAlgorithmForByteCode(serverKeyExchange.Signature.Algorithm)
	if algorithm.IsPkcs1 {
		hashed := cryptoHelpers.HashByteArray(algorithm.HashingAlgorithm, verifySignatureData)
		err := rsa.VerifyPKCS1v15(pubKey, algorithm.HashCode, hashed[:], serverKeyExchange.Signature.Content)
		if err != nil {
			log.Error(err)
			return false
		}
	}

	return true
}

func (serverKeyExchange ServerKeyExchange) SaveJSON() {
	file, _ := os.OpenFile("ServerKeyExchange.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverKeyExchange)
}

func (serverKeyExchange ServerKeyExchange) String() string {
	out := fmt.Sprintf("Server Key Exchange\n")
	out += fmt.Sprint(serverKeyExchange.RecordHeader)
	out += fmt.Sprint(serverKeyExchange.HandshakeHeader)
	out += fmt.Sprintf("  Curve Type.........: %6x\n", serverKeyExchange.Curve)
	out += fmt.Sprintf("  Curve..............: %6x - %s\n", serverKeyExchange.CurveID, constants.GCurves.GetCurveForByteCode(serverKeyExchange.CurveID))
	out += fmt.Sprintf("  Public Key length..: %6x\n", serverKeyExchange.PublicKeyLength)
	out += fmt.Sprintf("  Public Key.........: %6x\n", serverKeyExchange.PublicKey)
	out += fmt.Sprint(serverKeyExchange.Signature)
	return out
}

func (serverKeyExchange *ServerKeyExchange) MarshalJSON() ([]byte, error) {
	curveValue := constants.GCurves.GetCurveForByteCode(serverKeyExchange.CurveID)
	if curveValue == "" {
		curveValue = hex.EncodeToString(serverKeyExchange.CurveID[:])
	}
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
		Curve           string          `json:"Curve"`
		PublicKey       string          `json:"PublicKey"`
		Signature       Signature       `json:"Signature"`
	}{
		RecordHeader:    serverKeyExchange.RecordHeader,
		HandshakeHeader: serverKeyExchange.HandshakeHeader,
		Curve:           curveValue,
		PublicKey:       hex.EncodeToString(serverKeyExchange.PublicKey),
		Signature:       serverKeyExchange.Signature,
	})
}
