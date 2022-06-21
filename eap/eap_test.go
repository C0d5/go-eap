package eap

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEAPIdentity(t *testing.T) {
	e := EapPacket{}
	data, err := hex.DecodeString("020c000c0174657374303031")
	if err != nil {
		panic(err)
	}
	e.Decode(data)
	fmt.Printf("value is:  %v\n", e)
	e.Payload.String()
	t.Error()
}

func TestEAPTLS(t *testing.T) {
	e := EapPacket{}
	data, err := hex.DecodeString("020c00fd0d80000000f316030100ee010000ea030303260e8633d3254d5af5fc7b01877d066d750ba003ff280bebba696955bcb8b520a8179f8c2c76dd34aeae9d0bf7080870ddff5f368ee54e670f1af3118272becf0026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a1301130213030100007b000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b0009080304030303020301003300260024001d0020991076e4db6118ddf9f18622977472923fd08d7e59cda05da2905d9893b9d029")
	if err != nil {
		panic(err)
	}
	fmt.Printf("data: {%v}\n", data)
	e.Decode(data)
	fmt.Printf("value is:  %v\n", e)
	e.Payload.String()
	t.Error()
}
