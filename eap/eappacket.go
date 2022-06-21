package eap

import (
	"encoding/binary"
)

func GetEapPayload(msgType EapType) EapPayload {
	switch msgType {
	case Identity:
		return NewEapIdentity()
	case TLS:
		return &TLSPacket{}
	}
	return nil
}

//This function encodes the attributes of the header of an
//EAP message (code, id, length, type) and returns the encoded result in a slice.
//1º retval: If success encoding, return true, else false.
//2º retval: The encoded slice.
func (packet *EapPacket) Encode() (bool, []byte) {

	buff := make([]byte, 5)
	buff[0] = uint8(packet.code)
	buff[1] = uint8(packet.id)

	ok, payloadBuffer := packet.Payload.Encode()
	if !ok {
		return false, buff
	}
	binary.BigEndian.PutUint16(buff[2:], uint16(len(payloadBuffer)+5))

	if packet.code == EAPRequest || packet.code == EAPResponse {
		buff[4] = uint8(packet.msgType)
	}
	buff = append(buff, payloadBuffer...)
	return true, buff

}

//This function decodes from a given slice with raw data the attributes
//that belongs to the EAP header (code, identifier, length, type).
func (packet *EapPacket) Decode(buff []byte) bool {

	packet.code = EapCode(buff[0])
	packet.id = uint8(buff[1])
	packet.length = binary.BigEndian.Uint16(buff[2:])

	if packet.length != uint16(len(buff)) {
		return false
	}

	if len(buff) > 4 && (packet.code == EAPRequest || packet.code == EAPResponse) {
		packet.msgType = EapType(buff[4])
	}
	packet.Payload = GetEapPayload(packet.msgType)
	ok := packet.Payload.Decode(buff[5:])
	if !ok {
		return false
	}
	return true
}

func (packet *EapPacket) GetId() uint8 {
	return packet.id
}

func (packet *EapPacket) GetCode() EapCode {
	return packet.code
}

func (packet *EapPacket) SetId(id uint8) {
	packet.id = id
}

func (packet *EapPacket) SetCode(code EapCode) {
	packet.code = code
}

func (packet *EapPacket) GetType() EapType {
	return packet.msgType
}

func (packet *EapPacket) GetLength() uint16 {
	return packet.length
}

func (packet *EapPacket) setType(msgType EapType) {
	packet.msgType = msgType
}

func (packet *EapPacket) setLength(length uint16) {
	packet.length = length
}

func (packet *EapPacket) SetPayload(p *EapPayload) {
	packet.Payload = *p
}

func (packet *EapPacket) GetPayload() *EapPayload {
	return &packet.Payload
}
