package helpers

// Return payload data without the first 5 bytes corresponding to the RecordHeader
// Used for verifying the computed signature
func IgnoreRecordHeader(payload []byte) []byte {
	return payload[5:]
}