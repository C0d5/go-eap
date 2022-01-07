package constants

const (
	RecordHandshake        = 0x16
	RecordChangeCipherSpec = 0x14
	RecordApplicationData  = 0x17
	RecordEncryptedAlert   = 0x15
)

const (
	HandshakeClientHello       = 0x01
	HandshakeServerHello       = 0x02
	HandshakeServerCertificate = 0x0b
	HandshakeServerKeyExchange = 0x0c
	HandshakeServerHelloDone   = 0x0e
	HandshakeClientKeyExchange = 0x10
	HandshakeClientFinished    = 0x14
	HandshakeServerFinished    = 0x14
)
