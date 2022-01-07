package helpers

import (
	"encoding/binary"
)

func ConvertIntToByteArray(nr uint16) [2]byte {
	byteArray := make([]byte, 2)
	binary.BigEndian.PutUint16(byteArray, nr)
	var tmp [2]byte
	copy(tmp[:], byteArray)

	return tmp
}

func ConvertIntTo3ByteArray(nr uint16) [3]byte {
	byteArray := make([]byte, 2)
	binary.BigEndian.PutUint16(byteArray, nr)
	byteArray = append([]byte{0}, byteArray...)
	var tmp [3]byte
	copy(tmp[:], byteArray)

	return tmp
}

func ConvertByteArrayToUInt16(byteArray [2]byte) uint16 {
	return binary.BigEndian.Uint16(byteArray[:])
}

func Convert3ByteArrayToUInt32(byteArray [3]byte) uint32 {
	return binary.BigEndian.Uint32(append([]byte{0}, byteArray[:]...))
}
