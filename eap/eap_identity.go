package eap

type EapIdentity struct {
	identity string
}

func NewEapIdentity() *EapIdentity {
	identity := &EapIdentity{
		identity: "",
	}

	return identity
}

func (packet *EapIdentity) Encode() (bool, []byte) {
	return true, []byte(packet.identity)
}

func (packet *EapIdentity) Decode(buff []byte) bool {
	packet.identity = string(buff)
	return true
}

func (packet *EapIdentity) GetIdentity() string {
	return packet.identity
}

func (packet *EapIdentity) SetIdentity(value string) {
	packet.identity = value
}

func (packet *EapIdentity) String() string {
	return packet.identity
}
