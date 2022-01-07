package coreUtils

type AdditionalData struct {
	SeqNumber  byte
	RecordType byte
	TlsVersion [2]byte
}

func MakeAdditionalData(seqNumber byte, recordType byte, tlsVersion [2]byte) *AdditionalData {
	return &AdditionalData{
		SeqNumber:  seqNumber,
		RecordType: recordType,
		TlsVersion: tlsVersion,
	}
}

func (additionalData *AdditionalData) GetPayload() {
	//TODO implement this
}
