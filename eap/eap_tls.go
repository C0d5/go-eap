package eap

import (
	"encoding/binary"
	// "log"
)

type PacketFlag byte

const (
	FlagLength PacketFlag = 1 << 7
	FlagMore   PacketFlag = 1 << 6
	FlagStart  PacketFlag = 1 << 5
)

// 0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Code      |   Identifier  |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |---- Flags     |----  TLS Message Length
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |---- TLS Message Length        |----  TLS Data...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type PacketHeader struct {
	Outer  HeaderEap
	Flags  PacketFlag
	Length uint32
}

func (h *PacketHeader) Encode(buf []byte, dataLen int) []byte {

	if h.Flags&FlagLength != 0 {
		_, buf = h.Outer.Encode(dataLen + 5)
	} else {
		_, buf = h.Outer.Encode(dataLen + 1)
	}
	buf = append(buf, byte(h.Flags))
	if h.Flags&FlagLength != 0 {
		buf = append(buf,
			byte(h.Length>>24),
			byte(h.Length>>16),
			byte(h.Length>>8),
			byte(h.Length),
		)
	}
	return buf
}

func (h *PacketHeader) EncodedLen() int {
	l := 1 // flag (1 byte)
	if h.Flags&FlagLength != 0 {
		l += 4 // (length 4 bytes)
	}
	return l
}

// TLS Packet
type TLSPacket struct {
	PacketHeader
	Data []byte
}

func (p *TLSPacket) Encode() (bool, []byte) {
	buf := make([]byte, 0)
	buf = p.PacketHeader.Encode(buf, len(p.Data))
	return true, append(buf, p.Data...)
}

func (p *TLSPacket) Decode(buff []byte) bool {

	ok := p.PacketHeader.Outer.Decode(buff)
	if !ok {
		return false
	}
	if !ok {
		return false
	}
	if p.PacketHeader.Outer.GetType() != TLS {
		return false
	}
	if len(p.Data) < 1 {
		return false
	}
	if p.PacketHeader.Flags&FlagLength != 0 {
		if len(p.Data) < 4 {
			return false
		}
		p.PacketHeader.Length = binary.BigEndian.Uint32(buff)
		p.Data = buff[4:]
	}
	return true
}
