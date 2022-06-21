package eap

import (
	"encoding/binary"
	"fmt"
	// "log"
)

type PacketFlag byte

const (
	FlagLength     PacketFlag = 1 << 7
	FlagMore       PacketFlag = 1 << 6
	FlagStart      PacketFlag = 1 << 5
	FlagNone       PacketFlag = 0
	FlagLengthMore PacketFlag = 0xc0
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
	Flags  PacketFlag
	Length uint32
}

func (h *PacketHeader) Encode(dataLen int) []byte {
	l := 0
	if h.Flags&FlagLength != 0 {
		l = 5
	} else {
		l++
	}
	buf := make([]byte, dataLen+l)
	// fmt.Printf("PACKET HEADER: %d", h.Flags)
	buf[0] = byte(h.Flags)
	if h.Flags&FlagLength != 0 {
		// fmt.Printf("PACKET HEADER: Adding Length")
		buf[1] = byte(h.Length >> 24)
		buf[2] = byte(h.Length >> 16)
		buf[3] = byte(h.Length >> 8)
		buf[4] = byte(h.Length)
	}
	return buf
}

func (h *PacketHeader) Decode(buf []byte) bool {
	h.Flags = PacketFlag(buf[0])
	return true
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
	buff := p.PacketHeader.Encode(len(p.Data))
	copy(buff[p.PacketHeader.EncodedLen():], p.Data)
	return true, buff
}

func (p *TLSPacket) Decode(buff []byte) bool {
	fmt.Println("In TLS PACKET DECODE !!")
	ok := p.PacketHeader.Decode(buff)
	if !ok {
		return false
	}
	buff = buff[1:]
	if p.PacketHeader.Flags&FlagLength != 0 {
		if len(buff) < 4 {
			return false
		}
		p.PacketHeader.Length = binary.BigEndian.Uint32(buff)
		p.Data = buff[4:]
	}
	return true
}

func (p *TLSPacket) String() string {
	if (p.Flags != FlagStart) && p.Data == nil {
		return ""
	}
	return fmt.Sprintf("TLS Header: %v, Data: %v", p.PacketHeader, p.Data)
}
