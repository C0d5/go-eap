package eap

import "github.com/C0d5/go-tls/tls"

type TLSClient struct {
	tlsVersion [2]byte
	messages   []byte
	conn       *tls.Conn
}

func GetTLSClient(config *tls.Config) *TLSClient {
	return &TLSClient{
		conn: tls.Client(nil, config),
	}
}

type EapCode uint8
type EapType uint8

const (
	EAPRequest  EapCode = 1
	EAPResponse EapCode = 2
	EAPSuccess  EapCode = 3
	EAPFailure  EapCode = 4
)

const (
	Identity  EapType = 1
	LegacyNak EapType = 3
	Peap      EapType = 25
	MsChapv2  EapType = 26
	TLV       EapType = 33
	TLS       EapType = 13
)

//Interface that defines the functions common to any type of EAP message.
//Every EAP method should implement this interface.
type EapPacket interface {
	Decode(buff []byte) bool
	Encode() (bool, []byte)
	GetId() uint8
	GetCode() EapCode
	GetType() EapType
}

type HeaderEap struct {
	code    EapCode
	id      uint8
	length  uint16
	msgType EapType
}
