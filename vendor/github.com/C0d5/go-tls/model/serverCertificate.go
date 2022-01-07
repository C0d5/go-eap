package model

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/C0d5/go-tls/constants"
	"github.com/C0d5/go-tls/helpers"
	"os"
)

type Certificate struct {
	Length      [3]byte
	Content     []byte
	Certificate *x509.Certificate
}

func (certificate Certificate) String() string {
	out := fmt.Sprintf("  Certificate\n")
	out += fmt.Sprintf("    Certificate Length.: %x\n", certificate.Length)
	out += fmt.Sprintf("    Certificate........: %x\n", certificate.Content)
	out += fmt.Sprintf("    Certificate Public Key........: %x\n", certificate.Certificate.PublicKey.(*rsa.PublicKey).N)
	out += fmt.Sprintf("    Certificate Issuer............: %s\n", certificate.Certificate.Issuer)
	out += fmt.Sprintf("    Signature Algorithm...........: %s\n", certificate.Certificate.SignatureAlgorithm)
	return out
}

func (certificate *Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Length             uint32 `json:"Length"`
		Content            string `json:"Content"`
		Issuer             string `json:"Issuer"`
		SignatureAlgorithm string `json:"SignatureAlgorithm"`
	}{
		Length:             helpers.Convert3ByteArrayToUInt32(certificate.Length),
		Content:            hex.EncodeToString(certificate.Content),
		Issuer:             certificate.Certificate.Issuer.String(),
		SignatureAlgorithm: certificate.Certificate.SignatureAlgorithm.String(),
	})
}

type ServerCertificate struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	CertificateLength [3]byte
	Certificates      []Certificate
}

func ParseServerCertificate(answer []byte) (ServerCertificate, []byte, error) {
	var offset uint32
	offset = 0
	serverCertificate := ServerCertificate{}
	serverCertificate.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverCertificate.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverCertificate.HandshakeHeader.MessageType != constants.HandshakeServerCertificate {
		return serverCertificate, answer, helpers.ServerCertificateMissingError()
	}

	copy(serverCertificate.CertificateLength[:], answer[offset:offset+3])
	totalCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(serverCertificate.CertificateLength)
	offset += 3

	// Parsing list of certificates
	var readCertificateLength uint32
	readCertificateLength = 0
	for readCertificateLength < totalCertificateLengthInt {
		currentCertificate := Certificate{}
		copy(currentCertificate.Length[:], answer[offset:offset+3])
		offset += 3

		crtCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(currentCertificate.Length)

		currentCertificate.Content = answer[offset : offset+crtCertificateLengthInt]
		offset += crtCertificateLengthInt

		parsedCertificate, _ := x509.ParseCertificate(currentCertificate.Content)
		currentCertificate.Certificate = parsedCertificate

		serverCertificate.Certificates = append(serverCertificate.Certificates, currentCertificate)
		readCertificateLength += crtCertificateLengthInt + 3 // 3 - size of Length
	}

	return serverCertificate, answer, nil
}

// The server sends a sequence (chain) of certificates.
// According to the documentation, the sender's certificate MUST come first in the list.
// Each following certificate MUST directly certify the one preceding it.
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func (serverCertificate ServerCertificate) GetChosenCertificate() *x509.Certificate {
	if len(serverCertificate.Certificates) > 0 {
		return serverCertificate.Certificates[0].Certificate
	}
	return nil
}

func (serverCertificate ServerCertificate) SaveJSON() {
	file, _ := os.OpenFile("ServerCertificate.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverCertificate)
}

func (serverCertificate ServerCertificate) String() string {
	out := fmt.Sprintf("Server Certificate\n")
	out += fmt.Sprint(serverCertificate.RecordHeader)
	out += fmt.Sprint(serverCertificate.HandshakeHeader)
	out += fmt.Sprintf("  Certificate Lenght.: %x\n", serverCertificate.CertificateLength)
	out += fmt.Sprintf("Certificates:\n")

	for _, c := range serverCertificate.Certificates {
		out += fmt.Sprint(c)
	}
	return out
}

func (serverCertificate *ServerCertificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader      RecordHeader    `json:"RecordHeader"`
		HandshakeHeader   HandshakeHeader `json:"HandshakeHeader"`
		CertificateLength uint32          `json:"CertificatesLength"`
		Certificates      []Certificate   `json:"Certificates"`
	}{
		RecordHeader:      serverCertificate.RecordHeader,
		HandshakeHeader:   serverCertificate.HandshakeHeader,
		CertificateLength: helpers.Convert3ByteArrayToUInt32(serverCertificate.CertificateLength),
		Certificates:      serverCertificate.Certificates,
	})
}
