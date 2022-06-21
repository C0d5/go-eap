package eap

import (
	"github.com/C0d5/go-tls/tls"
)

type TLSClient struct {
	tlsVersion [2]byte
	messages   []byte
	Conn       *tls.Conn
	Session    *tls.ClientSessionState
	Hello      *tls.ClientHelloMsg
	Buf        []byte
}

func GetTLSClient(config *tls.Config) *TLSClient {
	return &TLSClient{
		Conn: tls.Client(nil, config),
	}
}

func (t *TLSClient) WriteHand(b []byte) {
	t.Conn.WriteHand(b)
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
type EapPayload interface {
	Decode(buff []byte) bool
	Encode() (bool, []byte)
	String() string
}

type EapPacket struct {
	code    EapCode
	id      uint8
	length  uint16
	msgType EapType
	Payload EapPayload
}
