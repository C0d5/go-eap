package eap

import (
	"encoding/binary"
	"log"
)

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

func GetEAPByType(msgType EapType) EapPacket {
	switch msgType {
	case Peap:
		return NewEapPeap()
	case Identity:
		return NewEapIdentity()
	case LegacyNak:
		return NewEapNak()
	case MsChapv2:
		return NewEapMsChapV2()
	case TLV:
		return NewEapTLVResult()
	}

	return &HeaderEap{}
}

type HeaderEap struct {
	code    EapCode
	id      uint8
	length  uint16
	msgType EapType
}

//This function encodes the attributes of the header of an
//EAP message (code, id, length, type) and returns the encoded result in a slice.
//1º retval: If success encoding, return true, else false.
//2º retval: The encoded slice.
func (packet *HeaderEap) Encode() (bool, []byte) {

	buff := make([]byte, packet.length)

	buff[0] = uint8(packet.code)
	buff[1] = uint8(packet.id)

	binary.BigEndian.PutUint16(buff[2:], packet.length)

	if packet.code == EAPRequest || packet.code == EAPResponse {
		buff[4] = uint8(packet.msgType)
	}

	return true, buff

}

func Decode(buff []byte, req EapPacket) (eapPacket EapPacket) {

	eapHeader := HeaderEap{
		code:   EapCode(buff[0]),
		length: binary.BigEndian.Uint16(buff[2:]),
	}

	if len(buff) <= 4 {
		return &eapHeader
	}

	eapHeader.setType(EapType(buff[4]))

	skip_change := false

	if len(buff) == 5 && eapHeader.code == EAPRequest &&
		eapHeader.length == 5 && eapHeader.msgType == Identity {
		skip_change = true
	}

	if len(buff) >= 5 && eapHeader.code == EAPRequest &&
		eapHeader.msgType == TLV {
		skip_change = true
	}

	if !skip_change && req != nil {
		newBuff := make([]byte, len(buff)+4)
		newBuff[0] = byte(req.GetCode())
		newBuff[1] = byte(req.GetId())
		binary.BigEndian.PutUint16(newBuff[2:], uint16(len(buff)+4))
		copy(newBuff[4:], buff)
		buff = newBuff
	}
	if !eapHeader.Decode(buff) || eapHeader.msgType == 0 {
		return &eapHeader
	}

	eapPacket = GetEAPByType(eapHeader.msgType)
	eapPacket.Decode(buff)

	return eapPacket
}

//This function decodes from a given slice with raw data the attributes
//that belongs to the EAP header (code, identifier, length, type).
func (packet *HeaderEap) Decode(buff []byte) bool {

	// length := uint16(len(buff))
	// log.Println(length)
	length := binary.BigEndian.Uint16(buff[2:4])

	if length != uint16(len(buff)) {
		log.Printf("len %d, %d\n", length, len(buff))
		return false
	}

	packet.code = EapCode(buff[0])
	packet.id = uint8(buff[1])

	packet.length = length

	if len(buff) > 4 && (packet.code == EAPRequest || packet.code == EAPResponse) {
		packet.msgType = EapType(buff[4])
	}

	return true

}

func (packet *HeaderEap) GetId() uint8 {
	return packet.id
}

func (packet *HeaderEap) GetCode() EapCode {
	return packet.code
}

func (packet *HeaderEap) SetId(id uint8) {
	packet.id = id
}

func (packet *HeaderEap) SetCode(code EapCode) {
	packet.code = code
}

func (packet *HeaderEap) GetType() EapType {
	return packet.msgType
}

func (packet *HeaderEap) GetLength() uint16 {
	return packet.length
}

func (packet *HeaderEap) setType(msgType EapType) {
	packet.msgType = msgType
}

func (packet *HeaderEap) setLength(length uint16) {
	packet.length = length
}