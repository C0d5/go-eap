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
	Outer  HeaderEap
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
	_, buf := h.Outer.Encode(dataLen + l)
	l = h.Outer.EncodedLen()
	// fmt.Printf("PACKET HEADER: %d", h.Flags)
	buf[l] = byte(h.Flags)
	if h.Flags&FlagLength != 0 {
		// fmt.Printf("PACKET HEADER: Adding Length")
		buf[l+1] = byte(h.Length >> 24)
		buf[l+2] = byte(h.Length >> 16)
		buf[l+3] = byte(h.Length >> 8)
		buf[l+4] = byte(h.Length)
	}
	return buf
}

func (h *PacketHeader) Decode(buf []byte) bool {
	ok := h.Outer.Decode(buf)
	if !ok {
		return false
	}
	i := h.Outer.EncodedLen()
	h.Flags = PacketFlag(buf[i])
	return true
}

func (h *PacketHeader) EncodedLen() int {
	l := 1 // flag (1 byte)
	if h.Flags&FlagLength != 0 {
		l += 4 // (length 4 bytes)
	}
	return l
}

func (h *PacketHeader) Len() int {
	return h.EncodedLen() + h.Outer.EncodedLen()
}

// TLS Packet
type TLSPacket struct {
	PacketHeader
	Data []byte
}

func (p *TLSPacket) Encode() (bool, []byte) {
	buff := p.PacketHeader.Encode(len(p.Data))
	copy(buff[p.PacketHeader.Len():], p.Data)
	return true, buff
}

func (p *TLSPacket) Decode(buff []byte) bool {
	fmt.Println("In TLS PACKET DECODE !!")
	ok := p.PacketHeader.Decode(buff)
	if !ok {
		return false
	}
	if p.PacketHeader.Outer.GetType() != TLS {
		return false
	}
	buff = buff[p.PacketHeader.Outer.EncodedLen()+1:]
	if p.PacketHeader.Flags&FlagLength != 0 {
		if len(buff) < 4 {
			return false
		}
		p.PacketHeader.Length = binary.BigEndian.Uint32(buff)
		p.Data = buff[4:]
	}
	return true
}
