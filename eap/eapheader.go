package eap

import (
	"encoding/binary"
	"log"
)

func GetEAPByType(msgType EapType) EapPacket {
	switch msgType {
	// case Peap:
	// 	return NewEapPeap()
	case Identity:
		return NewEapIdentity()
		// case LegacyNak:
		// 	return NewEapNak()
		// case MsChapv2:
		// 	return NewEapMsChapV2()
		// case TLV:
		// 	return NewEapTLVResult()
	}

	return nil
}

//This function encodes the attributes of the header of an
//EAP message (code, id, length, type) and returns the encoded result in a slice.
//1º retval: If success encoding, return true, else false.
//2º retval: The encoded slice.
func (packet *HeaderEap) Encode(dataLen int) (bool, []byte) {

	packet.length = uint16(packet.EncodedLen() + dataLen)
	buff := make([]byte, packet.length)
	buff[0] = byte(packet.code)
	buff[1] = byte(packet.id)
	buff[2] = byte(packet.length >> 8)
	buff[3] = byte(packet.length)

	if packet.code == EAPRequest || packet.code == EAPResponse {
		buff[4] = uint8(packet.msgType)
	}
	// fmt.Println("buff is : ----------\n  ", buff)
	return true, buff

}

func Decode(buff []byte, req EapPacket) (eapPacket EapPacket) {

	eapHeader := HeaderEap{
		code:   EapCode(buff[0]),
		length: binary.BigEndian.Uint16(buff[2:]),
	}

	if len(buff) <= 4 {
		return nil
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
		return nil
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

func (h *HeaderEap) HasType() bool {
	return h.code == EAPRequest || h.code == EAPResponse
}

func (h *HeaderEap) EncodedLen() int {
	l := 4 // code (1 byte) + identifier (1 byte) + length (2 bytes)
	if h.HasType() {
		l += 1 // type (1 byte)
	}
	return l
}

func GETHeader(c EapCode, i uint8, l uint16, m EapType) HeaderEap {
	return HeaderEap{
		code:    c,
		id:      i,
		length:  l,
		msgType: m,
	}
}
