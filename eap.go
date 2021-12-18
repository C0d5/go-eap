package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//go:generate stringer -type=PacketCode,PacketType -output gen_string.go

type PacketCode byte

const (
	CodeRequest  PacketCode = 1
	CodeResponse PacketCode = 2
	CodeSuccess  PacketCode = 3
	CodeFailure  PacketCode = 4
)

type PacketType byte

const (
	TypeIdentity PacketType = 1
	TypeTLS      PacketType = 13
)

type PacketHeader struct {
	Code       PacketCode
	Type       PacketType
	Identifier byte
}


type EAPItem struct {
	PacketHeader
	Msg string
	Avps *[]AVP
}